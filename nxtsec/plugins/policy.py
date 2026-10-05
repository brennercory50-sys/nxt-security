"""Authorization policy: decides whether a module may run against a target.

Checked twice for every assessment: when it is planned, and again when it
starts running (the scope file may have changed or expired in between).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from nxtsec.core.errors import PluginError, ScopeViolation
from nxtsec.core.models import Mode, Target, TargetType
from nxtsec.plugins.base import Permission, PluginManifest, RiskLevel
from nxtsec.safety.scope import Scope

if TYPE_CHECKING:
    from nxtsec.config.settings import Settings

DEFAULT_GRANTABLE = frozenset(Permission) - {Permission.RAW_SOCKET, Permission.LAB_ONLY_VALIDATION}


@dataclass(frozen=True)
class Policy:
    grantable: frozenset[Permission] = DEFAULT_GRANTABLE
    max_risk_real: RiskLevel = RiskLevel.MEDIUM
    max_cidr_hosts: int = 4096
    require_attestation: bool = True

    @classmethod
    def from_settings(cls, settings: Settings) -> Policy:
        return cls(
            max_risk_real=RiskLevel(str(settings.get("safety.max_risk_real", "medium"))),
            max_cidr_hosts=int(settings.get("safety.max_cidr_hosts", 4096)),
            require_attestation=bool(settings.get("safety.require_attestation", True)),
        )

    def authorize(
        self,
        manifest: PluginManifest,
        target: Target | None,
        mode: Mode,
        scope: Scope,
        now: datetime | None = None,
    ) -> frozenset[Permission]:
        """Return granted permissions, or raise if the module must not run."""
        # LAB and REAL are strictly separate worlds.
        if target is not None:
            if mode == Mode.LAB and target.type != TargetType.LAB:
                raise PluginError("LAB mode only accepts lab: targets")
            if mode == Mode.REAL and target.type == TargetType.LAB:
                raise PluginError("lab: targets require LAB mode")

        grantable = set(self.grantable)
        if mode == Mode.LAB:
            grantable |= {Permission.LAB_ONLY_VALIDATION, Permission.RAW_SOCKET}
        else:
            if manifest.risk_level.rank > self.max_risk_real.rank:
                raise PluginError(
                    f"{manifest.name} is {manifest.risk_level.value} risk; "
                    "only permitted in LAB mode"
                )
            if Permission.LAB_ONLY_VALIDATION in manifest.permissions:
                raise PluginError(f"{manifest.name} performs lab-only validation")

        missing = manifest.permissions - grantable
        if missing:
            raise PluginError(
                f"{manifest.name} requests ungranted permissions: "
                + ", ".join(sorted(p.value for p in missing))
            )

        if target is None:
            if manifest.target_types:
                raise PluginError(f"{manifest.name} requires a target")
            return frozenset(manifest.permissions)

        if manifest.target_types and target.type not in manifest.target_types:
            raise PluginError(f"{manifest.name} does not accept {target.type.value} targets")

        if manifest.needs_network and target.is_network:
            if self.require_attestation and mode == Mode.REAL and not scope.attestation:
                raise ScopeViolation(
                    f"scope '{scope.name}' has no operator_attestation; REAL-mode network "
                    "operations are refused until you attest you are authorized"
                )
            if target.type == TargetType.CIDR:
                size = ipaddress.ip_network(target.value).num_addresses
                if size > self.max_cidr_hosts:
                    raise PluginError(
                        f"{target.value} has {size} addresses; limit is {self.max_cidr_hosts} "
                        "(raise safety.max_cidr_hosts if intended)"
                    )
            scope.enforce(target, now)  # raises ScopeViolation
        return frozenset(manifest.permissions)


__all__ = ["Policy", "ScopeViolation"]
