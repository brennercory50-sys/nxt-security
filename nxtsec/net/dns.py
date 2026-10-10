"""DNS client (dnspython) returning normalized :class:`DnsRecord` observations.

Uses the system resolver configuration unless explicit nameservers are given
(``dns.nameservers`` in config). On platforms without a resolver config
(some Termux installs) set nameservers explicitly.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename

from nxtsec.core.errors import NxtSecError
from nxtsec.core.observations import DnsRecord

SUPPORTED_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR", "SRV")


class DnsError(NxtSecError):
    """The resolver could not be configured or used."""


@dataclass
class DnsAnswer:
    name: str
    rtype: str
    status: str  # ok | nxdomain | nodata | timeout | error
    records: list[DnsRecord] = field(default_factory=list)
    rdata: list[Any] = field(default_factory=list)  # dnspython rdata objects, for parsing
    detail: str | None = None


def normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def txt_value(rdata: Any) -> str:
    """TXT/SPF rdata as one string (character-strings concatenated, no quotes)."""
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


def _present(rtype: str, rdata: Any) -> str:
    if rtype == "TXT":
        return txt_value(rdata)
    text: str = rdata.to_text()
    return text.rstrip(".") if rtype in ("CNAME", "NS", "PTR") else text


class DnsClient:
    def __init__(
        self,
        nameservers: Sequence[str] = (),
        *,
        port: int = 53,
        timeout: float = 5.0,
    ) -> None:
        try:
            self._resolver = dns.resolver.Resolver(configure=not nameservers)
        except dns.resolver.NoResolverConfiguration as exc:
            raise DnsError(
                "no system DNS configuration found; set dns.nameservers in config"
            ) from exc
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.port = port
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    @property
    def nameservers(self) -> list[str]:
        return [str(n) for n in self._resolver.nameservers]

    def query(self, name: str, rtype: str) -> DnsAnswer:
        rtype = rtype.upper()
        if rtype not in SUPPORTED_TYPES:
            raise DnsError(f"unsupported record type {rtype!r}")
        qname = normalize_name(name)
        try:
            answer = self._resolver.resolve(qname, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(qname, rtype, "nxdomain")
        except dns.resolver.NoNameservers as exc:
            return DnsAnswer(qname, rtype, "error", detail=f"no nameserver answered: {exc}")
        except dns.exception.Timeout:
            return DnsAnswer(qname, rtype, "timeout", detail="query timed out")
        except dns.exception.DNSException as exc:
            return DnsAnswer(qname, rtype, "error", detail=str(exc))
        if answer.rrset is None:
            return DnsAnswer(qname, rtype, "nodata")
        ttl = int(answer.rrset.ttl)
        owner = normalize_name(answer.rrset.name.to_text())
        rdata = list(answer.rrset)
        records = [DnsRecord(owner, rtype, _present(rtype, r), ttl) for r in rdata]
        return DnsAnswer(qname, rtype, "ok", records, rdata)

    def reverse(self, address: str) -> DnsAnswer:
        rev = dns.reversename.from_address(address).to_text()
        ans = self.query(rev, "PTR")
        ans.name = address
        return ans
