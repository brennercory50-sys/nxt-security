"""Authorization scope engine.

A scope is an explicit allow-list (plus optional deny-list) of networks and
hostnames the operator is authorized to test. Deny always wins. Anything not
matched is out of scope: the default is refusal.

Example ``scope.yaml``::

    name: home-lab
    operator_attestation: "I own or am authorized to test these systems."
    allow:
      - 192.168.1.0/24
      - 10.10.10.0/24
      - localhost
      - authorized.example.com
      - "*.lab.example.com"
    deny:
      - 192.168.1.1
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nxtsec.core.errors import ConfigError, ScopeViolation, TargetError
from nxtsec.core.models import Target, TargetType

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    rule: str | None = None


@dataclass
class _RuleSet:
    networks: list[IPNetwork] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    wildcards: list[str] = field(default_factory=list)  # stored as ".suffix"
    loopback: bool = False

    @classmethod
    def build(cls, entries: Iterable[str]) -> _RuleSet:
        rs = cls()
        for raw in entries:
            if not isinstance(raw, str) or not raw.strip():
                raise ConfigError(f"invalid scope entry: {raw!r}")
            e = raw.strip().lower().rstrip(".")
            if e in _LOOPBACK_NAMES:
                rs.loopback = True
                continue
            if e.startswith("*."):
                rs.wildcards.append(e[1:])
                continue
            try:
                rs.networks.append(ipaddress.ip_network(e, strict=False))
                continue
            except ValueError:
                pass
            if "/" in e or ":" in e or " " in e:
                raise ConfigError(f"invalid scope entry: {raw!r}")
            rs.hosts.add(e)
        return rs

    def match_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        if self.loopback and ip.is_loopback:
            return "localhost"
        for net in self.networks:
            if ip.version == net.version and ip in net:
                return str(net)
        return None

    def match_net(self, net: IPNetwork) -> str | None:
        """A CIDR target matches only if it is entirely inside one allowed network."""
        if self.loopback and net.network_address.is_loopback and net.broadcast_address.is_loopback:
            return "localhost"
        for allowed in self.networks:
            if net.version == allowed.version and net.subnet_of(allowed):  # type: ignore[arg-type,unused-ignore]
                return str(allowed)
        return None

    def overlaps_net(self, net: IPNetwork) -> str | None:
        for n in self.networks:
            if net.version == n.version and net.overlaps(n):  # type: ignore[arg-type,unused-ignore]
                return str(n)
        return None

    def match_host(self, host: str) -> str | None:
        if self.loopback and host in _LOOPBACK_NAMES:
            return "localhost"
        if host in self.hosts:
            return host
        for suffix in self.wildcards:
            if host.endswith(suffix) and host != suffix[1:]:
                return f"*{suffix}"
        return None


class Scope:
    def __init__(
        self,
        allow: Iterable[str],
        deny: Iterable[str] = (),
        *,
        name: str = "default",
        attestation: str | None = None,
    ) -> None:
        self.name = name
        self.attestation = attestation
        self.allow_entries = list(allow)
        self.deny_entries = list(deny)
        self._allow = _RuleSet.build(self.allow_entries)
        self._deny = _RuleSet.build(self.deny_entries)

    @classmethod
    def empty(cls) -> Scope:
        return cls([], name="empty")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scope:
        if not isinstance(data, dict):
            raise ConfigError("scope file must be a mapping")
        allow = data.get("allow") or []
        deny = data.get("deny") or []
        if not isinstance(allow, list) or not isinstance(deny, list):
            raise ConfigError("scope 'allow' and 'deny' must be lists")
        return cls(
            allow,
            deny,
            name=str(data.get("name", "default")),
            attestation=data.get("operator_attestation"),
        )

    @classmethod
    def load(cls, path: Path) -> Scope:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read scope file {path}: {exc}") from exc
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"malformed scope file {path}: {exc}") from exc
        return cls.from_dict(data)

    def check(self, target: Target) -> ScopeDecision:
        if target.type == TargetType.FILE:
            return ScopeDecision(True, "local file targets are not network-scoped")
        if target.type == TargetType.LAB:
            return ScopeDecision(True, "lab targets are governed by the lab engine")
        host = target.host
        if host is None:
            return ScopeDecision(False, "target has no network identity")

        if target.type == TargetType.CIDR:
            net = ipaddress.ip_network(host, strict=False)
            if (rule := self._deny.overlaps_net(net)) is not None:
                return ScopeDecision(False, "range overlaps a denied network", rule)
            if (rule := self._allow.match_net(net)) is not None:
                return ScopeDecision(True, "range inside allowed network", rule)
            return ScopeDecision(False, "range is not fully inside any allowed network")

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        if ip is not None:
            if (rule := self._deny.match_ip(ip)) is not None:
                return ScopeDecision(False, "address is explicitly denied", rule)
            if (rule := self._allow.match_ip(ip)) is not None:
                return ScopeDecision(True, "address inside allowed network", rule)
            return ScopeDecision(False, "address is not in scope")

        if (rule := self._deny.match_host(host)) is not None:
            return ScopeDecision(False, "hostname is explicitly denied", rule)
        if (rule := self._allow.match_host(host)) is not None:
            return ScopeDecision(True, "hostname is allowed", rule)
        return ScopeDecision(False, "hostname is not in scope")

    def enforce(self, target: Target) -> ScopeDecision:
        """Return the decision if allowed; raise :class:`ScopeViolation` otherwise."""
        d = self.check(target)
        if not d.allowed:
            raise ScopeViolation(f"{target.raw!r} is out of scope ({d.reason}) [scope={self.name}]")
        return d

    def check_raw(self, raw: str) -> ScopeDecision:
        from nxtsec.targets.parser import parse_target

        try:
            return self.check(parse_target(raw))
        except TargetError as exc:
            return ScopeDecision(False, f"invalid target: {exc}")
