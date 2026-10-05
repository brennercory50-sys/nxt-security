"""Authorization policy: decides whether a module may run against a target."""

from __future__ import annotations

from dataclasses import dataclass

from nxtsec.core.errors import PluginError, ScopeViolation
from nxtsec.core.models import Mode, Target
from nxtsec.plugins.base import Permission, PluginManifest, RiskLevel
from nxtsec.safety.scope import Scope

DEFAULT_GRANTABLE = frozenset(Permission) - {Permission.RAW_SOCKET, Permission.LAB_ONLY_VALIDATION}


@dataclass(frozen=True)
class Policy:
    grantable: frozenset[Permission] = DEFAULT_GRANTABLE
    max_risk_real: RiskLevel = RiskLevel.MEDIUM

    def authorize(
        self, manifest: PluginManifest, target: Target | None, mode: Mode, scope: Scope
    ) -> frozenset[Permission]:
        """Return granted permissions, or raise if the module must not run."""
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

        if target is not None:
            if manifest.target_types and target.type not in manifest.target_types:
                raise PluginError(f"{manifest.name} does not accept {target.type.value} targets")
            if manifest.needs_network and target.is_network:
                scope.enforce(target)  # raises ScopeViolation
        elif manifest.target_types:
            raise PluginError(f"{manifest.name} requires a target")
        return frozenset(manifest.permissions)


__all__ = ["Policy", "ScopeViolation"]
