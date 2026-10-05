"""Layered configuration.

Precedence (lowest -> highest):

1. built-in defaults (this file)
2. ``config/config.yaml`` in the project, or the file given by ``--config`` / ``NXTSEC_CONFIG``
3. ``config/local.yaml`` (git-ignored, per-machine overrides)
4. environment variables ``NXTSEC_<SECTION>__<KEY>`` (e.g. ``NXTSEC_LOGGING__LEVEL=DEBUG``)

Credentials are never read from YAML; they come only from the environment.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from nxtsec.core.errors import ConfigError
from nxtsec.platform.detect import default_home

DEFAULTS: dict[str, Any] = {
    "operator": None,
    "paths": {"home": None, "scope_file": "config/scope.yaml", "plugins_dir": "plugins"},
    "database": {"url": None},
    "logging": {"level": "INFO", "console": True, "json": False, "file": True},
    "tools": {},
    "execution": {"default_timeout": 60, "max_output_bytes": 10485760},
    "ai": {"provider": None, "providers": {}},
    "scheduler": {"enabled": False},
    "lab": {"enabled": True, "docker_network": "nxtsec-lab"},
}
_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce(v: str) -> Any:
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(v)
    except ValueError:
        return v


def _env_overrides(env: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in env.items():
        if not key.startswith("NXTSEC_") or "__" not in key:
            continue
        parts = key[len("NXTSEC_") :].lower().split("__")
        node = out
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = _coerce(val)
    return out


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at the top level")
    return data


@dataclass
class Settings:
    data: dict[str, Any]
    project_root: Path
    sources: list[str]

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def _resolve(self, value: str) -> Path:
        p = Path(value).expanduser()
        return p if p.is_absolute() else self.project_root / p

    @property
    def home(self) -> Path:
        h = self.get("paths.home")
        return Path(h).expanduser() if h else default_home()

    @property
    def scope_file(self) -> Path:
        return self._resolve(str(self.get("paths.scope_file")))

    @property
    def plugins_dir(self) -> Path:
        return self._resolve(str(self.get("paths.plugins_dir")))

    @property
    def database_url(self) -> str:
        url = self.get("database.url")
        return str(url) if url else f"sqlite:///{self.home / 'nxtsec.db'}"

    @property
    def log_dir(self) -> Path:
        return self.home / "logs"

    @property
    def operator(self) -> str:
        op = self.get("operator")
        if op:
            return str(op)
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

    def validate(self) -> None:
        level = str(self.get("logging.level", "INFO")).upper()
        if level not in _LEVELS:
            raise ConfigError(f"logging.level must be one of {sorted(_LEVELS)}")
        t = self.get("execution.default_timeout")
        if not isinstance(t, (int, float)) or t <= 0:
            raise ConfigError("execution.default_timeout must be a positive number")
        if not isinstance(self.get("tools"), dict):
            raise ConfigError("tools must be a mapping of tool name -> settings")


def find_project_root(start: Path | None = None) -> Path:
    here = (start or Path.cwd()).resolve()
    for p in (here, *here.parents):
        if (p / "config" / "config.yaml").is_file() and (p / "nxtsec").is_dir():
            return p
    return Path(__file__).resolve().parents[2]


def load_settings(
    config_path: Path | None = None,
    env: dict[str, str] | None = None,
    project_root: Path | None = None,
) -> Settings:
    e = dict(os.environ if env is None else env)
    root = project_root or find_project_root()
    data = copy.deepcopy(DEFAULTS)
    sources = ["defaults"]

    explicit = config_path or (Path(e["NXTSEC_CONFIG"]) if e.get("NXTSEC_CONFIG") else None)
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"config file not found: {explicit}")
        files = [explicit]
    else:
        files = [
            p
            for p in (root / "config" / "config.yaml", root / "config" / "local.yaml")
            if p.is_file()
        ]
    for f in files:
        data = _merge(data, _read_yaml(f))
        sources.append(str(f))

    env_over = _env_overrides(e)
    if env_over:
        data = _merge(data, env_over)
        sources.append("environment")

    s = Settings(data=data, project_root=root, sources=sources)
    s.validate()
    return s
