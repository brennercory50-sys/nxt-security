"""Detect the host platform and compute per-platform default directories.

Paths are never hard-coded across platforms: each OS gets its own
conventional location, and everything can be overridden with
``NXTSEC_HOME``.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PlatformInfo:
    system: str  # "windows" | "linux" | "macos" | "termux" | other
    release: str
    machine: str
    python: str
    is_termux: bool
    is_admin: bool

    @property
    def label(self) -> str:
        return {
            "windows": "Windows",
            "linux": "Linux",
            "macos": "macOS",
            "termux": "Android/Termux",
        }.get(self.system, self.system)


def _is_termux(env: dict[str, str]) -> bool:
    prefix = env.get("PREFIX", "")
    return "com.termux" in prefix or bool(env.get("TERMUX_VERSION"))


def _is_admin(system: str) -> bool:
    if system == "windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def detect_platform(env: dict[str, str] | None = None) -> PlatformInfo:
    e = dict(os.environ if env is None else env)
    raw = platform.system().lower()
    termux = raw == "linux" and _is_termux(e)
    system = "termux" if termux else {"darwin": "macos"}.get(raw, raw)
    return PlatformInfo(
        system=system,
        release=platform.release(),
        machine=platform.machine(),
        python=sys.version.split()[0],
        is_termux=termux,
        is_admin=_is_admin(system),
    )


def default_home(info: PlatformInfo | None = None, env: dict[str, str] | None = None) -> Path:
    """Data directory for databases, evidence and logs."""
    e = dict(os.environ if env is None else env)
    if e.get("NXTSEC_HOME"):
        return Path(e["NXTSEC_HOME"]).expanduser()
    info = info or detect_platform(e)
    if info.system == "windows":
        base = e.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "NXT-Security"
    if info.system == "macos":
        return Path.home() / "Library" / "Application Support" / "NXT-Security"
    xdg = e.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(xdg) / "nxt-security"
