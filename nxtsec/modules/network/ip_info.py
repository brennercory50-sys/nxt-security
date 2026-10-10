"""``ip.info``: classify an IP address and look up its PTR records.

Classification is offline (stdlib ``ipaddress``): global, private, loopback,
link-local, reserved, multicast, unspecified. For a hostname target the name
is resolved first (subject to the scope resolution guard). ASN/geo enrichment
via an external API is deferred to the OSINT engine.
"""

from __future__ import annotations

import ipaddress

from nxtsec.core.models import Target, TargetType
from nxtsec.core.observations import IpInfo
from nxtsec.net.dns import DnsClient, DnsError
from nxtsec.net.resolve import LookupTimeout, is_ip, resolve_host
from nxtsec.plugins.base import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    RiskLevel,
)


def classify(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    return "global"


class IpInfoModule(Plugin):
    manifest = PluginManifest(
        name="ip.info",
        version="0.1.0",
        description="Classify an IP (global/private/…) and resolve its PTR records",
        category="network",
        author="NXT-Security",
        permissions=frozenset({Permission.NETWORK_ACCESS}),
        risk_level=RiskLevel.LOW,
        target_types=frozenset(
            {
                TargetType.IPV4,
                TargetType.IPV6,
                TargetType.DOMAIN,
                TargetType.HOSTNAME,
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
            addresses = [host]
        else:
            try:
                addresses = resolve_host(host, timeout)
            except (OSError, LookupTimeout) as exc:
                res.errors.append(f"cannot resolve {host}: {exc}")
                return res

        try:
            client: DnsClient | None = DnsClient(
                ctx.setting("dns.nameservers", []) or [], timeout=timeout
            )
        except DnsError as exc:
            client = None
            res.errors.append(f"PTR lookups unavailable: {exc}")

        for addr in addresses:
            ctx.check_cancelled()
            ip = ipaddress.ip_address(addr)
            ptr: list[str] = []
            if client is not None:
                ans = client.reverse(addr)
                if ans.status == "ok":
                    ptr = [r.value for r in ans.records]
                elif ans.status in ("timeout", "error"):
                    res.errors.append(f"PTR {addr}: {ans.detail}")
            res.add(IpInfo(address=addr, version=ip.version, classification=classify(ip), ptr=ptr))
        return res
