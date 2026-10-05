"""Tool registry: metadata and health detection for external tools.

Detection only. NXT-Security never installs anything; it reports the
install method so the operator can decide.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nxtsec.core.errors import CommandError
from nxtsec.plugins.base import RiskLevel
from nxtsec.safety.execution import resolve_binary, run_command

ALL_PLATFORMS = frozenset({"windows", "linux", "macos", "termux"})


class ToolStatus(str, Enum):
    INSTALLED = "INSTALLED"
    MISSING = "MISSING"
    OUTDATED = "OUTDATED"
    BROKEN = "BROKEN"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    category: str
    binary: str
    version_args: tuple[str, ...]
    version_regex: str
    documentation: str
    install: Mapping[str, str]
    required: bool = False
    min_version: str | None = None
    capabilities: tuple[str, ...] = ()
    risk_level: RiskLevel = RiskLevel.PASSIVE
    platforms: frozenset[str] = ALL_PLATFORMS
    windows_binary: str | None = None

    def binary_for(self, system: str) -> str:
        return self.windows_binary if system == "windows" and self.windows_binary else self.binary

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "binary": self.binary,
            "version_command": [self.binary, *self.version_args],
            "install_method": dict(self.install),
            "documentation": self.documentation,
            "required": self.required,
            "min_version": self.min_version,
            "capabilities": list(self.capabilities),
            "risk_level": self.risk_level.value,
            "platforms": sorted(self.platforms),
        }


@dataclass
class ToolState:
    spec: ToolSpec
    status: ToolStatus
    path: str | None = None
    version: str | None = None
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.spec.name,
            "status": self.status.value,
            "path": self.path,
            "version": self.version,
            "required": self.spec.required,
            "category": self.spec.category,
            "detail": self.detail,
        }


def parse_version(text: str) -> tuple[int, ...] | None:
    m = re.match(r"(\d+(?:\.\d+)*)", text)
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def version_lt(a: str, b: str) -> bool:
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        return False
    n = max(len(va), len(vb))
    return va + (0,) * (n - len(va)) < vb + (0,) * (n - len(vb))


def _install(apt: str, win: str, brew: str | None = None, pkg: str | None = None) -> dict[str, str]:
    return {
        "linux": f"sudo apt install {apt}",
        "windows": win,
        "macos": f"brew install {brew or apt}",
        "termux": f"pkg install {pkg or apt}",
    }


BUILTIN_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "python",
        "Python interpreter",
        "runtime",
        "python3",
        ("--version",),
        r"Python\s+(\d+\.\d+\.\d+)",
        "https://docs.python.org/3/",
        _install("python3", "winget install Python.Python.3.12", "python", "python"),
        required=True,
        min_version="3.10",
        windows_binary="python",
    ),
    ToolSpec(
        "git",
        "Version control",
        "runtime",
        "git",
        ("--version",),
        r"git version\s+(\d+\.\d+(?:\.\d+)?)",
        "https://git-scm.com/doc",
        _install("git", "winget install Git.Git"),
        required=True,
    ),
    ToolSpec(
        "nmap",
        "Network discovery and service detection",
        "network",
        "nmap",
        ("--version",),
        r"Nmap version\s+(\d+\.\d+)",
        "https://nmap.org/book/",
        _install("nmap", "winget install Insecure.Nmap"),
        min_version="7.80",
        capabilities=("host_discovery", "port_scan", "service_detection"),
        risk_level=RiskLevel.MEDIUM,
    ),
    ToolSpec(
        "tshark",
        "Packet capture and protocol analysis",
        "network",
        "tshark",
        ("--version",),
        r"TShark \(Wireshark\)\s+(\d+\.\d+\.\d+)",
        "https://www.wireshark.org/docs/man-pages/tshark.html",
        _install("tshark", "winget install WiresharkFoundation.Wireshark", "wireshark"),
        capabilities=("pcap_read", "packet_capture"),
        risk_level=RiskLevel.LOW,
    ),
    ToolSpec(
        "dig",
        "DNS lookup utility",
        "dns",
        "dig",
        ("-v",),
        r"DiG\s+(\d+\.\d+\.\d+)",
        "https://bind9.readthedocs.io/",
        _install("dnsutils", "winget install ISC.Bind", "bind", "dnsutils"),
        capabilities=("dns_query",),
        risk_level=RiskLevel.LOW,
    ),
    ToolSpec(
        "whois",
        "WHOIS client",
        "osint",
        "whois",
        ("--version",),
        r"(?:Version|whois)\s+(\d+\.\d+(?:\.\d+)?)",
        "https://www.rfc-editor.org/rfc/rfc3912",
        _install("whois", "winget install Microsoft.Sysinternals.Whois"),
        capabilities=("whois_lookup",),
        risk_level=RiskLevel.LOW,
    ),
    ToolSpec(
        "curl",
        "HTTP client",
        "web",
        "curl",
        ("--version",),
        r"curl\s+(\d+\.\d+\.\d+)",
        "https://curl.se/docs/",
        _install("curl", "built into Windows 10+"),
        capabilities=("http_request",),
        risk_level=RiskLevel.LOW,
    ),
    ToolSpec(
        "openssl",
        "TLS and crypto toolkit",
        "crypto",
        "openssl",
        ("version",),
        r"OpenSSL\s+(\d+\.\d+\.\d+)",
        "https://www.openssl.org/docs/",
        _install("openssl", "winget install ShiningLight.OpenSSL.Light"),
        capabilities=("tls_inspect", "cert_parse"),
    ),
    ToolSpec(
        "yara",
        "Pattern matching for malware triage",
        "forensics",
        "yara",
        ("--version",),
        r"(\d+\.\d+\.\d+)",
        "https://yara.readthedocs.io/",
        _install("yara", "winget install VirusTotal.YARA"),
        capabilities=("yara_scan",),
    ),
    ToolSpec(
        "docker",
        "Container runtime for the lab engine",
        "lab",
        "docker",
        ("--version",),
        r"Docker version\s+(\d+\.\d+\.\d+)",
        "https://docs.docker.com/",
        _install("docker.io", "winget install Docker.DockerDesktop", "--cask docker"),
        capabilities=("lab_containers",),
        platforms=frozenset({"windows", "linux", "macos"}),
    ),
)


class ToolRegistry:
    def __init__(
        self,
        specs: tuple[ToolSpec, ...] = BUILTIN_TOOLS,
        overrides: Mapping[str, Any] | None = None,
        system: str = "linux",
        timeout: float = 15.0,
    ) -> None:
        self._specs = {s.name: s for s in specs}
        self._overrides = dict(overrides or {})
        self.system = system
        self.timeout = timeout

    def specs(self) -> list[ToolSpec]:
        return sorted(self._specs.values(), key=lambda s: (s.category, s.name))

    def get(self, name: str) -> ToolSpec:
        try:
            return self._specs[name]
        except KeyError:
            raise KeyError(f"unknown tool: {name}") from None

    def configured_path(self, name: str) -> str | None:
        o = self._overrides.get(name)
        if isinstance(o, Mapping) and o.get("path"):
            return str(o["path"])
        return None

    def check(self, name: str) -> ToolState:
        spec = self.get(name)
        if self.system not in spec.platforms:
            return ToolState(spec, ToolStatus.UNSUPPORTED, detail=f"not supported on {self.system}")
        explicit = self.configured_path(name)
        path = resolve_binary(spec.binary_for(self.system), explicit)
        if path is None:
            detail = (
                f"configured path not executable: {explicit}"
                if explicit
                else f"install: {spec.install.get(self.system, 'see documentation')}"
            )
            return ToolState(spec, ToolStatus.MISSING, detail=detail)
        try:
            res = run_command(
                [path, *spec.version_args], timeout=self.timeout, max_output=64 * 1024
            )
        except CommandError as exc:
            return ToolState(spec, ToolStatus.BROKEN, path=path, detail=str(exc))
        out = res.stdout + "\n" + res.stderr
        m = re.search(spec.version_regex, out)
        if m is None:
            status = ToolStatus.BROKEN if not res.ok else ToolStatus.INSTALLED
            detail = (
                f"version command exited {res.returncode}"
                if not res.ok
                else "version not recognized"
            )
            return ToolState(spec, status, path=path, detail=detail)
        version = m.group(1)
        if spec.min_version and version_lt(version, spec.min_version):
            return ToolState(
                spec, ToolStatus.OUTDATED, path, version, f"requires >= {spec.min_version}"
            )
        return ToolState(spec, ToolStatus.INSTALLED, path, version)

    def check_all(self) -> list[ToolState]:
        return [self.check(s.name) for s in self.specs()]
