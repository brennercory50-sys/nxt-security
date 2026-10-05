"""``dns.resolve``: forward (A/AAAA) and reverse (PTR) lookups via the system resolver.

Full record-type support (MX, NS, TXT, SOA, CNAME) arrives with the recon
engine in Phase 8; this module only uses the OS resolver.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

from nxtsec.core.models import Target, TargetType
from nxtsec.core.net import LookupTimeout, bounded_call, is_ip, resolve_host
from nxtsec.plugins.base import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    RiskLevel,
)


class DnsResolve(Plugin):
    manifest = PluginManifest(
        name="dns.resolve",
        version="0.1.0",
        description="Resolve A/AAAA via the system resolver; reverse DNS for addresses",
        category="dns",
        author="NXT-Security",
        permissions=frozenset({Permission.NETWORK_ACCESS}),
        risk_level=RiskLevel.LOW,
        target_types=frozenset(
            {
                TargetType.DOMAIN,
                TargetType.HOSTNAME,
                TargetType.IPV4,
                TargetType.IPV6,
                TargetType.URL,
            }
        ),
    )

    def run(self, target: Target | None, ctx: ModuleContext) -> ModuleResult:
        ctx.require(Permission.NETWORK_ACCESS)
        assert target is not None and target.host is not None
        timeout = ctx.option_float("timeout", 5.0, 0.5, 60.0)
        host = target.host
        res = ModuleResult()

        if is_ip(host):
            try:
                name, aliases, _ = bounded_call(lambda: socket.gethostbyaddr(host), timeout)
            except (socket.herror, socket.gaierror) as exc:
                res.errors.append(f"no PTR record for {host}: {exc}")
            except LookupTimeout as exc:
                res.errors.append(f"reverse lookup of {host} {exc}")
            else:
                res.observations.append(
                    {"type": "dns.ptr", "address": host, "names": [name, *aliases]}
                )
            return res

        try:
            addresses = resolve_host(host, timeout)
        except socket.gaierror as exc:
            res.errors.append(f"{host} did not resolve: {exc}")
            return res
        except LookupTimeout as exc:
            res.errors.append(f"lookup of {host} {exc}")
            return res

        for addr in addresses:
            ip = ipaddress.ip_address(addr)
            obs: dict[str, Any] = {
                "type": "dns.address",
                "name": host,
                "record": "A" if ip.version == 4 else "AAAA",
                "address": addr,
            }
            res.observations.append(obs)

        decision = ctx.scope.check_resolution(host, addresses)
        if not decision.allowed:
            # Resolution itself is fine; flag that connecting would be refused.
            res.observations.append(
                {"type": "scope.notice", "name": host, "detail": decision.reason}
            )
        return res
