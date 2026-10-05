"""Authorization scope engine.

A scope is an explicit allow-list (plus optional deny-list) of networks and
hostnames the operator is authorized to test. Deny always wins. Anything not
matched is out of scope: the default is refusal.

Example ``scope.yaml``::

    name: client-x-2026q4
    operator_attestation: "I have written authorization from Client X (ref SOW-118)."
    expires: 2026-12-31            # whole scope stops working after this date
    allow:
      - 192.168.1.0/24
      - localhost
      - authorized.example.com
      - "*.lab.example.com"
      - target: 10.10.10.0/24      # per-rule expiry and note
        expires: 2026-11-15
        note: "staging network, test window only"
    deny:
      - 192.168.1.1

Dates without a time mean "through the end of that day, UTC".
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from nxtsec.core.errors import ConfigError, ScopeViolation, TargetError
from nxtsec.core.models import Target, TargetType
from nxtsec.targets.parser import parse_target, validate_hostname

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})
_LOOPBACK_NETS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)
_MIN_ALLOW_PREFIX = 8  # refuse 0.0.0.0/0-style allow rules
_TOP_LEVEL_KEYS = frozenset({"name", "operator_attestation", "expires", "allow", "deny"})
_RULE_KEYS = frozenset({"target", "expires", "note"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def parse_expiry(value: Any, where: str = "expires") -> datetime | None:
    """Parse a YAML date/datetime/ISO string into an aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day, 23, 59, 59)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ConfigError(f"{where}: invalid date {value!r} (use YYYY-MM-DD)") from exc
        if len(text) == 10:
            dt = dt.replace(hour=23, minute=59, second=59)
    else:
        raise ConfigError(f"{where}: invalid date {value!r}")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _subnet_of(a: IPNetwork, b: IPNetwork) -> bool:
    if isinstance(a, ipaddress.IPv4Network) and isinstance(b, ipaddress.IPv4Network):
        return a.subnet_of(b)
    if isinstance(a, ipaddress.IPv6Network) and isinstance(b, ipaddress.IPv6Network):
        return a.subnet_of(b)
    return False


def _overlaps(a: IPNetwork, b: IPNetwork) -> bool:
    return a.version == b.version and a.overlaps(b)


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    rule: str | None = None


@dataclass(frozen=True)
class ScopeRule:
    entry: str
    kind: str  # "loopback" | "network" | "host" | "wildcard"
    value: str
    network: IPNetwork | None = None
    expires: datetime | None = None
    note: str | None = None

    def active(self, now: datetime) -> bool:
        return self.expires is None or now <= self.expires

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.entry,
            "expires": self.expires.isoformat() if self.expires else None,
            "note": self.note,
        }


def _build_rule(raw: Any, *, is_allow: bool) -> ScopeRule:
    where = "allow" if is_allow else "deny"
    expires: datetime | None = None
    note: str | None = None
    entry: Any = raw
    if isinstance(raw, dict):
        unknown = set(raw) - _RULE_KEYS
        if unknown:
            raise ConfigError(f"{where} rule has unknown keys: {sorted(unknown)}")
        entry = raw.get("target")
        expires = parse_expiry(raw.get("expires"), f"{where} rule {entry!r}")
        note = str(raw["note"]) if raw.get("note") is not None else None
    if not isinstance(entry, str) or not entry.strip():
        raise ConfigError(f"invalid {where} entry: {raw!r}")
    e = entry.strip().lower().rstrip(".")

    if e in _LOOPBACK_NAMES:
        return ScopeRule(e, "loopback", e, expires=expires, note=note)
    if e.startswith("*."):
        try:
            base = validate_hostname(e[2:])
        except TargetError as exc:
            raise ConfigError(f"invalid wildcard {entry!r}: {exc}") from exc
        if "." not in base:
            raise ConfigError(f"wildcard {entry!r} is too broad (needs at least two labels)")
        return ScopeRule(e, "wildcard", "." + base, expires=expires, note=note)
    try:
        net = ipaddress.ip_network(e, strict=False)
    except ValueError:
        pass
    else:
        if is_allow and net.prefixlen < _MIN_ALLOW_PREFIX:
            raise ConfigError(
                f"allow rule {entry!r} is overly broad (prefix < /{_MIN_ALLOW_PREFIX})"
            )
        return ScopeRule(e, "network", str(net), network=net, expires=expires, note=note)
    try:
        host = validate_hostname(e)
    except TargetError as exc:
        raise ConfigError(f"invalid {where} entry {entry!r}") from exc
    return ScopeRule(e, "host", host, expires=expires, note=note)


class _Rules:
    def __init__(self, rules: Sequence[ScopeRule]) -> None:
        self.rules = list(rules)

    def _active(self, now: datetime) -> Iterable[ScopeRule]:
        return (r for r in self.rules if r.active(now))

    def match_ip(self, ip: IPAddress, now: datetime) -> ScopeRule | None:
        for r in self._active(now):
            if r.kind == "loopback" and ip.is_loopback:
                return r
            if (
                r.kind == "network"
                and r.network is not None
                and ip.version == r.network.version
                and ip in r.network
            ):
                return r
        return None

    def contains_net(self, net: IPNetwork, now: datetime) -> ScopeRule | None:
        """The whole of ``net`` lies inside one active rule."""
        for r in self._active(now):
            if r.kind == "loopback" and any(_subnet_of(net, lb) for lb in _LOOPBACK_NETS):
                return r
            if r.kind == "network" and r.network is not None and _subnet_of(net, r.network):
                return r
        return None

    def overlaps_net(self, net: IPNetwork, now: datetime) -> ScopeRule | None:
        for r in self._active(now):
            if r.kind == "loopback" and any(_overlaps(net, lb) for lb in _LOOPBACK_NETS):
                return r
            if r.kind == "network" and r.network is not None and _overlaps(net, r.network):
                return r
        return None

    def match_host(self, host: str, now: datetime) -> ScopeRule | None:
        for r in self._active(now):
            if r.kind == "loopback" and host in _LOOPBACK_NAMES:
                return r
            if r.kind == "host" and host == r.value:
                return r
            if r.kind == "wildcard" and host.endswith(r.value) and host != r.value[1:]:
                return r
        return None


class Scope:
    def __init__(
        self,
        allow: Iterable[Any],
        deny: Iterable[Any] = (),
        *,
        name: str = "default",
        attestation: str | None = None,
        expires: Any = None,
    ) -> None:
        self.name = name
        self.attestation = (attestation.strip() or None) if isinstance(attestation, str) else None
        self.expires = parse_expiry(expires, "scope expires")
        self.allow_rules = [_build_rule(x, is_allow=True) for x in allow]
        self.deny_rules = [_build_rule(x, is_allow=False) for x in deny]
        self._allow = _Rules(self.allow_rules)
        self._deny = _Rules(self.deny_rules)

    # -- construction ------------------------------------------------------
    @classmethod
    def empty(cls) -> Scope:
        return cls([], name="empty")

    @classmethod
    def from_dict(cls, data: Any) -> Scope:
        if not isinstance(data, dict):
            raise ConfigError("scope file must be a mapping")
        unknown = set(data) - _TOP_LEVEL_KEYS
        if unknown:
            raise ConfigError(f"scope file has unknown keys: {sorted(unknown)}")
        allow = data.get("allow") or []
        deny = data.get("deny") or []
        if not isinstance(allow, list) or not isinstance(deny, list):
            raise ConfigError("scope 'allow' and 'deny' must be lists")
        att = data.get("operator_attestation")
        if att is not None and not isinstance(att, str):
            raise ConfigError(
                f"operator_attestation must be a sentence, got {att!r} "
                "(note: YAML reads bare yes/no/true as booleans; quote your statement)"
            )
        return cls(
            allow,
            deny,
            name=str(data.get("name", "default")),
            attestation=att,
            expires=data.get("expires"),
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

    # -- introspection -----------------------------------------------------
    @property
    def allow_entries(self) -> list[str]:
        return [r.entry for r in self.allow_rules]

    @property
    def deny_entries(self) -> list[str]:
        return [r.entry for r in self.deny_rules]

    @property
    def fingerprint(self) -> str:
        """Stable hash of the authorization content, recorded on every assessment."""
        doc = {
            "name": self.name,
            "attestation": self.attestation,
            "expires": self.expires.isoformat() if self.expires else None,
            "allow": [r.to_dict() for r in self.allow_rules],
            "deny": [r.to_dict() for r in self.deny_rules],
        }
        return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()

    def is_expired(self, now: datetime | None = None) -> bool:
        return self.expires is not None and (now or _now()) > self.expires

    def expiring_within(self, window: timedelta, now: datetime | None = None) -> list[str]:
        """Human-readable list of the scope or rules that expire inside ``window``."""
        n = now or _now()
        out = []
        if self.expires and n <= self.expires <= n + window:
            out.append(f"scope '{self.name}' ({self.expires.date()})")
        for r in self.allow_rules:
            if r.expires and n <= r.expires <= n + window:
                out.append(f"{r.entry} ({r.expires.date()})")
        return out

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "attestation": self.attestation,
            "expires": self.expires.isoformat() if self.expires else None,
            "fingerprint": self.fingerprint,
            "allow": [r.to_dict() for r in self.allow_rules],
            "deny": [r.to_dict() for r in self.deny_rules],
        }

    # -- decisions ---------------------------------------------------------
    def check(self, target: Target, now: datetime | None = None) -> ScopeDecision:
        n = now or _now()
        if target.type == TargetType.FILE:
            return ScopeDecision(True, "local file targets are not network-scoped")
        if target.type == TargetType.LAB:
            return ScopeDecision(True, "lab targets are governed by the lab engine")
        if self.expires is not None and n > self.expires:
            return ScopeDecision(False, f"scope '{self.name}' expired on {self.expires.date()}")
        host = target.host
        if host is None:
            return ScopeDecision(False, "target has no network identity")

        if target.type == TargetType.CIDR:
            net = ipaddress.ip_network(host, strict=False)
            if (rule := self._deny.overlaps_net(net, n)) is not None:
                return ScopeDecision(False, "range overlaps a denied network", rule.entry)
            if (rule := self._allow.contains_net(net, n)) is not None:
                return ScopeDecision(True, "range inside allowed network", rule.entry)
            return ScopeDecision(False, "range is not fully inside any allowed network")

        try:
            ip: IPAddress | None = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        if ip is not None:
            if (rule := self._deny.match_ip(ip, n)) is not None:
                return ScopeDecision(False, "address is explicitly denied", rule.entry)
            if (rule := self._allow.match_ip(ip, n)) is not None:
                return ScopeDecision(True, "address inside allowed network", rule.entry)
            return ScopeDecision(False, "address is not in scope")

        if (rule := self._deny.match_host(host, n)) is not None:
            return ScopeDecision(False, "hostname is explicitly denied", rule.entry)
        if (rule := self._allow.match_host(host, n)) is not None:
            return ScopeDecision(True, "hostname is allowed", rule.entry)
        return ScopeDecision(False, "hostname is not in scope")

    def check_resolution(
        self, host: str, addresses: Sequence[str], now: datetime | None = None
    ) -> ScopeDecision:
        """Validate where an allowed hostname actually points before connecting.

        Prevents DNS-based pivots: an in-scope name must not resolve to a denied
        address, nor to an internal (private, loopback, link-local, reserved)
        address that is not itself explicitly in scope.
        """
        n = now or _now()
        if not addresses:
            return ScopeDecision(False, f"{host} did not resolve to any address")
        for raw in addresses:
            try:
                ip = ipaddress.ip_address(raw.split("%", 1)[0])
            except ValueError:
                return ScopeDecision(False, f"{host} resolved to an invalid address {raw!r}")
            if (rule := self._deny.match_ip(ip, n)) is not None:
                return ScopeDecision(False, f"{host} resolves to denied address {ip}", rule.entry)
            internal = (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_unspecified
                or ip.is_multicast
            )
            if internal and self._allow.match_ip(ip, n) is None:
                return ScopeDecision(
                    False,
                    f"{host} resolves to internal address {ip}, which is not in scope "
                    "(add the address or its network to the allow list if authorized)",
                )
        return ScopeDecision(True, f"{host} resolves only to permitted addresses")

    def enforce(self, target: Target, now: datetime | None = None) -> ScopeDecision:
        """Return the decision if allowed; raise :class:`ScopeViolation` otherwise."""
        d = self.check(target, now)
        if not d.allowed:
            raise ScopeViolation(f"{target.raw!r} is out of scope ({d.reason}) [scope={self.name}]")
        return d

    def check_raw(self, raw: str, now: datetime | None = None) -> ScopeDecision:
        try:
            return self.check(parse_target(raw), now)
        except TargetError as exc:
            return ScopeDecision(False, f"invalid target: {exc}")
