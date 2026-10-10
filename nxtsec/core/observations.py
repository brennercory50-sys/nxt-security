"""Normalized observation model.

Modules never emit free-form tool output. Every observation is one of these
types, serialized with ``to_dict()`` (which adds the ``type`` discriminator).
The correlation engine, reporters and the CLI rely on these shapes; see
``docs/data-model.md``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar


@dataclass(frozen=True)
class Observation:
    TYPE: ClassVar[str] = "observation"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.TYPE
        return d


@dataclass(frozen=True)
class Notice(Observation):
    """Something the operator should know that is neither data nor a finding."""

    TYPE: ClassVar[str] = "notice"
    subject: str
    detail: str
    level: str = "info"  # info | warning


@dataclass(frozen=True)
class DnsRecord(Observation):
    TYPE: ClassVar[str] = "dns.record"
    name: str
    rtype: str
    value: str
    ttl: int | None = None


@dataclass(frozen=True)
class Relationship(Observation):
    """A directed edge between two assets, e.g. ``example.com -mail_exchanger-> mx1.host``."""

    TYPE: ClassVar[str] = "relation"
    source: str
    relation: str
    target: str
    via: str | None = None  # which data produced the edge (dns, cert, ct, rdap, http)


@dataclass(frozen=True)
class PortState(Observation):
    TYPE: ClassVar[str] = "net.port"
    address: str
    port: int
    protocol: str
    state: str  # open | closed | filtered | unreachable
    latency_ms: float | None = None
    detail: str | None = None


@dataclass(frozen=True)
class IpInfo(Observation):
    TYPE: ClassVar[str] = "ip.info"
    address: str
    version: int
    classification: str
    ptr: list[str] = field(default_factory=list)
    asn: int | None = None
    asn_name: str | None = None
    asn_prefix: str | None = None
    asn_country: str | None = None
    asn_registry: str | None = None


@dataclass(frozen=True)
class HttpExchange(Observation):
    TYPE: ClassVar[str] = "http.response"
    url: str
    status: int
    reason: str
    headers: list[list[str]]
    peer: str
    elapsed_ms: float
    title: str | None = None
    content_type: str | None = None
    body_bytes: int = 0
    body_truncated: bool = False
    redirect_to: str | None = None
    tls_version: str | None = None
    tls_verified: bool | None = None
    tls_error: str | None = None


@dataclass(frozen=True)
class Technology(Observation):
    TYPE: ClassVar[str] = "tech"
    name: str
    category: str
    url: str
    version: str | None = None
    confidence: str = "medium"  # low | medium | high
    evidence: str = ""


@dataclass(frozen=True)
class Certificate(Observation):
    TYPE: ClassVar[str] = "tls.certificate"
    host: str
    port: int
    address: str
    subject: str
    issuer: str
    sans: list[str]
    serial: str
    not_before: str
    not_after: str
    days_remaining: int
    signature_algorithm: str | None
    key_type: str
    key_bits: int | None
    sha256: str
    self_signed: bool
    trusted: bool
    hostname_match: bool
    tls_version: str | None = None
    cipher: str | None = None
    trust_error: str | None = None


@dataclass(frozen=True)
class CtEntry(Observation):
    TYPE: ClassVar[str] = "ct.certificate"
    crtsh_id: int
    issuer: str
    names: list[str]
    not_before: str
    not_after: str
    serial: str
    expired: bool


@dataclass(frozen=True)
class Subdomain(Observation):
    TYPE: ClassVar[str] = "subdomain"
    name: str
    source: str
    in_scope: bool
    wildcard: bool = False


@dataclass(frozen=True)
class RdapRecord(Observation):
    TYPE: ClassVar[str] = "rdap"
    query: str
    object_class: str
    handle: str | None
    name: str | None
    source_url: str
    status: list[str] = field(default_factory=list)
    events: dict[str, str] = field(default_factory=dict)
    registrar: str | None = None
    nameservers: list[str] = field(default_factory=list)
    country: str | None = None
    start_address: str | None = None
    end_address: str | None = None
    cidrs: list[str] = field(default_factory=list)
    network_type: str | None = None


@dataclass(frozen=True)
class RobotsTxt(Observation):
    TYPE: ClassVar[str] = "web.robots_txt"
    url: str
    user_agents: list[str]
    disallow: list[str]
    allow: list[str]
    sitemaps: list[str]


@dataclass(frozen=True)
class SecurityTxt(Observation):
    TYPE: ClassVar[str] = "web.security_txt"
    url: str
    contacts: list[str]
    expires: str | None
    expired: bool | None
    policy: list[str] = field(default_factory=list)
    encryption: list[str] = field(default_factory=list)
    acknowledgments: list[str] = field(default_factory=list)
    preferred_languages: str | None = None
    canonical: list[str] = field(default_factory=list)
    hiring: list[str] = field(default_factory=list)
    signed: bool = False
    problems: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FileHashInfo(Observation):
    TYPE: ClassVar[str] = "file.hash"
    path: str
    size: int
    modified: str
    md5: str
    sha1: str
    sha256: str
    sha512: str


@dataclass(frozen=True)
class FileEntry(Observation):
    """A filesystem entry that was deliberately not read (symlink, FIFO, device)."""

    TYPE: ClassVar[str] = "file.entry"
    path: str
    kind: str  # symlink | special
    points_to: str | None = None
    reason: str | None = None


OBSERVATION_TYPES: dict[str, type[Observation]] = {
    cls.TYPE: cls
    for cls in (
        Notice,
        DnsRecord,
        Relationship,
        PortState,
        IpInfo,
        HttpExchange,
        Technology,
        Certificate,
        CtEntry,
        Subdomain,
        RdapRecord,
        RobotsTxt,
        SecurityTxt,
        FileHashInfo,
        FileEntry,
    )
}
