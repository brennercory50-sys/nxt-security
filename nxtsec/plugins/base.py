"""The contract every NXT-Security module and plugin implements.

A module declares *what it needs* (permissions) and *how dangerous it is*
(risk level) in its manifest. The framework, not the module, decides whether
it may run: permissions are granted by policy, and network modules only ever
receive targets that have already passed scope enforcement.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from nxtsec.core.errors import PluginError
from nxtsec.core.models import Evidence, Finding, Mode, Target, TargetType

if TYPE_CHECKING:
    import logging

    from nxtsec.events.bus import EventBus
    from nxtsec.safety.scope import Scope


class Permission(str, Enum):
    READ_ONLY = "READ_ONLY"
    LOCAL_FILES = "LOCAL_FILES"
    WRITE_FILES = "WRITE_FILES"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    RAW_SOCKET = "RAW_SOCKET"
    EXTERNAL_API = "EXTERNAL_API"
    EXEC_TOOLS = "EXEC_TOOLS"
    LAB_ONLY_VALIDATION = "LAB_ONLY_VALIDATION"


class RiskLevel(str, Enum):
    PASSIVE = "passive"  # reads public/local data, no contact with the target
    LOW = "low"  # light, standard requests (DNS lookup, one HTTP GET)
    MEDIUM = "medium"  # active probing (port scan, crawling)
    HIGH = "high"  # intrusive checks; LAB mode only unless explicitly allowed

    @property
    def rank(self) -> int:
        return list(RiskLevel).index(self)


_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class PluginManifest:
    name: str
    version: str
    description: str
    category: str
    author: str = "unknown"
    permissions: frozenset[Permission] = frozenset({Permission.READ_ONLY})
    risk_level: RiskLevel = RiskLevel.PASSIVE
    target_types: frozenset[TargetType] = frozenset()  # empty = targetless module
    platforms: frozenset[str] = frozenset({"windows", "linux", "macos", "termux"})
    requires_tools: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _NAME_RE.match(self.name):
            raise PluginError(f"invalid plugin name {self.name!r}")
        if not _VERSION_RE.match(self.version):
            raise PluginError(f"plugin {self.name}: version must be semver, got {self.version!r}")
        lab_only = Permission.LAB_ONLY_VALIDATION in self.permissions
        if self.risk_level == RiskLevel.HIGH and not lab_only:
            raise PluginError(
                f"plugin {self.name}: HIGH risk modules must declare LAB_ONLY_VALIDATION"
            )

    @property
    def needs_network(self) -> bool:
        return bool(
            self.permissions
            & {Permission.NETWORK_ACCESS, Permission.RAW_SOCKET, Permission.EXTERNAL_API}
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PluginManifest:
        try:
            return cls(
                name=str(d["name"]),
                version=str(d["version"]),
                description=str(d.get("description", "")),
                category=str(d.get("category", "custom")),
                author=str(d.get("author", "unknown")),
                permissions=frozenset(Permission(p) for p in d.get("permissions", ["READ_ONLY"])),
                risk_level=RiskLevel(d.get("risk_level", "passive")),
                target_types=frozenset(TargetType(t) for t in d.get("target_types", [])),
                platforms=frozenset(d.get("platforms", ["windows", "linux", "macos", "termux"])),
                requires_tools=tuple(d.get("requires_tools", [])),
            )
        except (KeyError, ValueError) as exc:
            raise PluginError(f"invalid manifest: {exc}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "author": self.author,
            "permissions": sorted(p.value for p in self.permissions),
            "risk_level": self.risk_level.value,
            "target_types": sorted(t.value for t in self.target_types),
            "platforms": sorted(self.platforms),
            "requires_tools": list(self.requires_tools),
        }


@dataclass
class ModuleContext:
    """Everything a module may use. Modules must not reach around it."""

    assessment_id: str
    mode: Mode
    scope: Scope
    granted: frozenset[Permission]
    logger: logging.Logger
    bus: EventBus
    settings: dict[str, Any] = field(default_factory=dict)

    def require(self, perm: Permission) -> None:
        if perm not in self.granted:
            raise PluginError(f"permission {perm.value} was not granted to this module")


@dataclass
class ModuleResult:
    observations: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Plugin(ABC):
    """Base class for every module. Subclasses set ``manifest`` and implement ``run``."""

    manifest: PluginManifest

    @abstractmethod
    def run(self, target: Target | None, ctx: ModuleContext) -> ModuleResult:
        """Execute against an already scope-checked ``target``."""
