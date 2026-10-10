"""``network.tcp_connect``: TCP connect test against a short list of ports.

This is a connectivity check, not a port scanner: it is capped at 1024 ports
and 8 addresses, and uses full connects only. Broad discovery belongs to the
Nmap integration (Phase 9).
"""

from __future__ import annotations

import socket
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

from nxtsec.core.errors import PluginError, ScopeViolation
from nxtsec.core.models import Target, TargetType
from nxtsec.net.resolve import LookupTimeout, is_ip, resolve_host
from nxtsec.plugins.base import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    RiskLevel,
    option_lookup,
    parse_float_option,
)

NAME = "network.tcp_connect"
DEFAULT_PORTS = (22, 80, 443)
MAX_PORTS = 1024
MAX_ADDRESSES = 8
MAX_WORKERS = 32
# Windows retries a refused SYN before reporting it (~1-2 s), so a short default
# timeout would misreport closed ports as "filtered" there.
DEFAULT_TIMEOUT = 3.0


def parse_ports(raw: str | None) -> list[int]:
    """Parse ``"22,80,8000-8010"``. Raises PluginError on anything invalid."""
    if raw is None or not raw.strip():
        raise PluginError("no ports given")
    ports: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
                if lo > hi:
                    raise ValueError
                rng = range(lo, hi + 1)
            else:
                rng = range(int(part), int(part) + 1)
        except ValueError:
            raise PluginError(f"invalid port specification {part!r}") from None
        if len(ports) + len(rng) > MAX_PORTS * 2:
            raise PluginError(f"too many ports (max {MAX_PORTS})")
        for p in rng:
            if not 1 <= p <= 65535:
                raise PluginError(f"port out of range: {p}")
            ports.add(p)
    if not ports:
        raise PluginError("no ports given")
    if len(ports) > MAX_PORTS:
        raise PluginError(f"too many ports (max {MAX_PORTS})")
    return sorted(ports)


def _url_port(target: Target) -> int:
    parts = urlsplit(target.value)
    return parts.port or (443 if parts.scheme == "https" else 80)


def probe(address: str, port: int, timeout: float) -> dict[str, Any]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    t0 = time.monotonic()
    state, detail = "open", None
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((address, port))
        except ConnectionRefusedError:
            state = "closed"
        except TimeoutError:
            state = "filtered"
        except OSError as exc:
            state, detail = "unreachable", exc.strerror or str(exc)
    obs: dict[str, Any] = {
        "type": "tcp.port",
        "address": address,
        "port": port,
        "state": state,
        "latency_ms": round((time.monotonic() - t0) * 1000, 1),
    }
    if detail:
        obs["detail"] = detail
    return obs


class TcpConnect(Plugin):
    manifest = PluginManifest(
        name=NAME,
        version="0.1.0",
        description="TCP connect test to a short port list (full scans: Nmap integration)",
        category="network",
        author="NXT-Security",
        permissions=frozenset({Permission.NETWORK_ACCESS}),
        risk_level=RiskLevel.MEDIUM,
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

    @classmethod
    def validate_options(cls, options: Mapping[str, str]) -> None:
        ports = option_lookup(options, NAME, "ports")
        if ports is not None:
            parse_ports(ports)
        parse_float_option(
            option_lookup(options, NAME, "timeout"), "timeout", DEFAULT_TIMEOUT, 0.1, 30.0
        )

    def run(self, target: Target | None, ctx: ModuleContext) -> ModuleResult:
        ctx.require(Permission.NETWORK_ACCESS)
        assert target is not None and target.host is not None
        raw_ports = ctx.option("ports")
        if raw_ports is not None:
            ports = parse_ports(raw_ports)
        elif target.type == TargetType.URL:
            ports = [_url_port(target)]
        else:
            ports = list(DEFAULT_PORTS)
        timeout = ctx.option_float("timeout", DEFAULT_TIMEOUT, 0.1, 30.0)

        host = target.host
        if is_ip(host):
            addresses = [host]
        else:
            try:
                addresses = resolve_host(host, timeout=max(timeout, 5.0))
            except (socket.gaierror, LookupTimeout) as exc:
                raise PluginError(f"cannot resolve {host}: {exc}") from exc
            decision = ctx.scope.check_resolution(host, addresses)
            if not decision.allowed:
                raise ScopeViolation(decision.reason)
        addresses = addresses[:MAX_ADDRESSES]

        res = ModuleResult()
        pairs = [(a, p) for a in addresses for p in ports]
        ctx.check_cancelled()
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(pairs))) as pool:
            futures = [pool.submit(probe, a, p, timeout) for a, p in pairs]
            for fut in futures:
                res.observations.append(fut.result())
        ctx.check_cancelled()
        res.observations.sort(key=lambda o: (o["address"], o["port"]))
        open_count = sum(o["state"] == "open" for o in res.observations)
        ctx.logger.info(f"{open_count}/{len(pairs)} ports open")
        return res
