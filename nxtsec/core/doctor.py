"""System health checks behind ``nxtsec doctor``.

Every check returns a :class:`Check`; checks never raise. Overall status:
READY (no errors, nothing required missing), DEGRADED (warnings or optional
tools missing), NOT READY (an error or a required component missing).
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from nxtsec.config.settings import Settings
from nxtsec.core.errors import NxtSecError
from nxtsec.database.store import open_database
from nxtsec.integrations.tools import ToolRegistry, ToolStatus
from nxtsec.platform.detect import PlatformInfo
from nxtsec.plugins.registry import PluginRegistry
from nxtsec.safety.redaction import SENSITIVE_KEY
from nxtsec.safety.scope import Scope

MIN_PYTHON = (3, 10)
LOW_DISK_BYTES = 1 * 1024**3


class Level(str, Enum):
    OK = "OK"
    WARN = "WARN"
    MISSING = "MISSING"
    ERROR = "ERROR"


@dataclass
class Check:
    section: str
    name: str
    level: Level
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "section": self.section,
            "name": self.name,
            "level": self.level.value,
            "detail": self.detail,
        }


@dataclass
class DoctorReport:
    checks: list[Check]

    @property
    def overall(self) -> str:
        if any(c.level == Level.ERROR for c in self.checks):
            return "NOT READY"
        if any(c.level in (Level.WARN, Level.MISSING) for c in self.checks):
            return "DEGRADED"
        return "READY"

    def to_dict(self) -> dict[str, Any]:
        counts = {lvl.value: sum(c.level == lvl for c in self.checks) for lvl in Level}
        return {
            "overall": self.overall,
            "counts": counts,
            "checks": [c.to_dict() for c in self.checks],
        }


class Doctor:
    def __init__(
        self,
        settings: Settings,
        platform: PlatformInfo,
        tools: ToolRegistry,
        plugins: Callable[[], PluginRegistry],
        env: dict[str, str] | None = None,
    ) -> None:
        self.settings = settings
        self.platform = platform
        self.tools = tools
        self._plugins = plugins
        self.env = dict(os.environ if env is None else env)

    def run(self) -> DoctorReport:
        checks: list[Check] = []
        for fn in (
            self._platform,
            self._python,
            self._tools,
            self._config,
            self._scope,
            self._filesystem,
            self._storage,
            self._database,
            self._plugins_check,
            self._network,
            self._permissions,
            self._environment,
        ):
            try:
                checks.extend(fn())
            except Exception as exc:  # noqa: BLE001 - doctor must always produce a report
                checks.append(Check("internal", fn.__name__.strip("_"), Level.ERROR, str(exc)))
        return DoctorReport(checks)

    # -- individual checks -------------------------------------------------
    def _platform(self) -> list[Check]:
        p = self.platform
        out = [Check("system", "Platform", Level.OK, f"{p.label} {p.release} ({p.machine})")]
        if p.is_termux:
            out.append(
                Check(
                    "system",
                    "Termux",
                    Level.WARN,
                    "Termux detected: raw sockets and packet capture are unavailable "
                    "without root",
                )
            )
        return out

    def _python(self) -> list[Check]:
        v = sys.version_info
        lvl = Level.OK if (v.major, v.minor) >= MIN_PYTHON else Level.ERROR
        return [
            Check(
                "system",
                "Python",
                lvl,
                f"{v.major}.{v.minor}.{v.micro} at {sys.executable}"
                + ("" if lvl == Level.OK else f" (requires >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"),
            )
        ]

    def _tools(self) -> list[Check]:
        out = []
        for st in self.tools.check_all():
            if st.spec.name == "python":
                continue  # covered by the running interpreter check
            if st.status == ToolStatus.INSTALLED:
                lvl, detail = Level.OK, f"{st.version or 'unknown version'} ({st.path})"
            elif st.status == ToolStatus.MISSING:
                lvl = Level.ERROR if st.spec.required else Level.MISSING
                detail = st.detail
            elif st.status == ToolStatus.UNSUPPORTED:
                lvl, detail = Level.OK, f"n/a: {st.detail}"
            else:
                lvl = Level.ERROR if st.spec.required else Level.WARN
                detail = f"{st.status.value}: {st.detail}"
            out.append(Check("tools", st.spec.name, lvl, detail))
        return out

    def _config(self) -> list[Check]:
        s = self.settings
        out = [Check("config", "Configuration", Level.OK, ", ".join(s.sources))]
        for name, conf in (s.get("tools") or {}).items():
            if isinstance(conf, dict) and "path" in conf and not Path(str(conf["path"])).is_file():
                out.append(
                    Check(
                        "config",
                        f"tools.{name}.path",
                        Level.WARN,
                        f"configured path does not exist: {conf['path']}",
                    )
                )
        return out

    def _scope(self) -> list[Check]:
        path = self.settings.scope_file
        if not path.is_file():
            return [
                Check(
                    "config",
                    "Scope",
                    Level.WARN,
                    f"no scope file at {path}; all network targets will be refused. "
                    "Run: nxtsec config init-scope",
                )
            ]
        try:
            sc = Scope.load(path)
        except NxtSecError as exc:
            return [Check("config", "Scope", Level.ERROR, str(exc))]
        if not sc.allow_entries:
            return [Check("config", "Scope", Level.WARN, f"scope '{sc.name}' allows nothing")]
        return [
            Check(
                "config",
                "Scope",
                Level.OK,
                f"'{sc.name}': {len(sc.allow_entries)} allow, {len(sc.deny_entries)} deny",
            )
        ]

    def _filesystem(self) -> list[Check]:
        home = self.settings.home
        try:
            home.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=home, prefix=".doctor-", delete=True) as fh:
                fh.write(b"ok")
        except OSError as exc:
            return [Check("system", "Data directory", Level.ERROR, f"{home}: {exc}")]
        return [Check("system", "Data directory", Level.OK, f"{home} (writable)")]

    def _storage(self) -> list[Check]:
        home = self.settings.home
        target = home if home.exists() else Path(home.anchor or "/")
        free = shutil.disk_usage(target).free
        gb = free / 1024**3
        lvl = Level.OK if free >= LOW_DISK_BYTES else Level.WARN
        return [Check("system", "Storage", lvl, f"{gb:.1f} GiB free")]

    def _database(self) -> list[Check]:
        try:
            db = open_database(self.settings.database_url)
            ver = db.schema_version()
            db.close()
        except NxtSecError as exc:
            return [Check("system", "Database", Level.ERROR, str(exc))]
        return [Check("system", "Database", Level.OK, f"SQLite schema v{ver}")]

    def _plugins_check(self) -> list[Check]:
        reg = self._plugins()
        out = [Check("system", "Plugins", Level.OK, f"{len(reg)} registered")]
        for name, err in reg.load_errors.items():
            out.append(Check("system", f"plugin {name}", Level.WARN, err))
        return out

    def _network(self) -> list[Check]:
        try:
            names = [n for _, n in socket.if_nameindex()]
        except (OSError, AttributeError):
            names = []
        out = [
            Check(
                "network",
                "Interfaces",
                Level.OK if names else Level.WARN,
                ", ".join(names) if names else "could not enumerate interfaces",
            )
        ]
        try:
            socket.getaddrinfo("localhost", None)
            out.append(Check("network", "Name resolution", Level.OK, "localhost resolves"))
        except OSError as exc:
            out.append(Check("network", "Name resolution", Level.WARN, str(exc)))
        return out

    def _permissions(self) -> list[Check]:
        if self.platform.is_admin:
            return [
                Check(
                    "system",
                    "Privileges",
                    Level.WARN,
                    "running as administrator/root; prefer an unprivileged account",
                )
            ]
        return [
            Check(
                "system",
                "Privileges",
                Level.OK,
                "unprivileged (raw-socket features will be unavailable)",
            )
        ]

    def _environment(self) -> list[Check]:
        nx = sorted(k for k in self.env if k.startswith("NXTSEC_"))
        out = [
            Check(
                "config",
                "Environment",
                Level.OK,
                f"{len(nx)} NXTSEC_* variable(s)" + (f": {', '.join(nx)}" if nx else ""),
            )
        ]
        # Credentials must not live in YAML config.
        leaked = _find_sensitive_values(self.settings.data)
        if leaked:
            out.append(
                Check(
                    "config",
                    "Credentials in config",
                    Level.ERROR,
                    "move these to environment variables: " + ", ".join(leaked),
                )
            )
        return out


def _find_sensitive_values(node: Any, prefix: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, str) and v and SENSITIVE_KEY.search(str(k)) and not k.endswith("_env"):
                hits.append(key)
            else:
                hits.extend(_find_sensitive_values(v, key))
    return hits
