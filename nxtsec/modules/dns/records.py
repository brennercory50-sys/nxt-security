"""``dns.records``: enumerate common DNS record types and derive relationships.

Queries A, AAAA, CNAME, MX, NS, TXT, SOA and CAA for a domain via the DNS
client, emits normalized DnsRecord observations plus relationship edges
(mail_exchanger, name_server, alias_of), and raises informational/low
findings for mail-security posture (missing SPF, missing DMARC, overly broad
SPF) that an authorized owner would want to know about their own domain.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from nxtsec.core.models import (
    Confidence,
    Finding,
    Severity,
    Target,
    TargetType,
)
from nxtsec.core.observations import DnsRecord, Relationship
from nxtsec.net.dns import DnsClient, DnsError, txt_value
from nxtsec.plugins.base import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    RiskLevel,
)

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
_SPF_ALL = re.compile(r"(?P<qual>[-~?+]?)all\b")


def _client(ctx: ModuleContext) -> DnsClient:
    nameservers = ctx.setting("dns.nameservers", []) or []
    timeout = ctx.option_float("timeout", 5.0, 0.5, 60.0)
    return DnsClient(nameservers, timeout=timeout)


def analyze_spf(record: str) -> list[str]:
    """Return human notes about an SPF record's ``all`` qualifier."""
    notes = []
    m = _SPF_ALL.search(record)
    if m is None:
        notes.append("SPF record has no 'all' mechanism; evaluation is undefined")
    elif m.group("qual") == "+":
        notes.append("SPF ends with '+all', which authorizes any sender")
    elif m.group("qual") == "?":
        notes.append("SPF ends with '?all' (neutral); provides no protection")
    return notes


class DnsRecords(Plugin):
    manifest = PluginManifest(
        name="dns.records",
        version="0.1.0",
        description="Enumerate A/AAAA/CNAME/MX/NS/TXT/SOA/CAA and mail-security posture",
        category="dns",
        author="NXT-Security",
        permissions=frozenset({Permission.NETWORK_ACCESS}),
        risk_level=RiskLevel.LOW,
        target_types=frozenset({TargetType.DOMAIN, TargetType.HOSTNAME, TargetType.URL}),
    )

    @classmethod
    def validate_options(cls, options):  # type: ignore[no-untyped-def]
        from nxtsec.plugins.base import option_lookup, parse_float_option

        parse_float_option(
            option_lookup(options, cls.manifest.name, "timeout"), "timeout", 5.0, 0.5, 60.0
        )

    def run(self, target: Target | None, ctx: ModuleContext) -> ModuleResult:
        ctx.require(Permission.NETWORK_ACCESS)
        assert target is not None and target.host is not None
        domain = target.host
        res = ModuleResult()
        try:
            client = _client(ctx)
        except DnsError as exc:
            res.errors.append(str(exc))
            return res
        ctx.logger.info(f"querying DNS for {domain} via {','.join(client.nameservers) or 'system'}")

        txt_records: list[str] = []
        for rtype in RECORD_TYPES:
            ctx.check_cancelled()
            ans = client.query(domain, rtype)
            if ans.status == "ok":
                res.add(*ans.records)
                self._relationships(domain, rtype, ans.records, res)
                if rtype == "TXT":
                    txt_records = [r.value for r in ans.records]
            elif ans.status in ("timeout", "error"):
                res.errors.append(f"{rtype} query {ans.status}: {ans.detail}")
            elif ans.status == "nxdomain":
                res.errors.append(f"{domain} does not exist (NXDOMAIN)")
                return res

        self._mail_security(domain, txt_records, client, res, ctx)
        return res

    @staticmethod
    def _relationships(
        domain: str, rtype: str, records: Sequence[DnsRecord], res: ModuleResult
    ) -> None:
        rel = {"MX": "mail_exchanger", "NS": "name_server", "CNAME": "alias_of"}.get(rtype)
        if not rel:
            return
        for r in records:
            value = r.value.split()[-1] if rtype == "MX" else r.value
            res.add(Relationship(domain, rel, value.rstrip("."), via="dns"))

    def _mail_security(
        self,
        domain: str,
        txt_records: list[str],
        client: DnsClient,
        res: ModuleResult,
        ctx: ModuleContext,
    ) -> None:
        spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
        if not spf:
            res.findings.append(
                Finding(
                    title=f"No SPF record for {domain}",
                    severity=Severity.LOW,
                    target=domain,
                    detection_module="",
                    confidence=Confidence.FIRM,
                    cwe="CWE-290",
                    description="The domain publishes no SPF (v=spf1) TXT record.",
                    impact="Receivers cannot verify which hosts may send mail for this domain, "
                    "easing sender spoofing.",
                    remediation="Publish an SPF record of authorized senders, ending in '-all'.",
                    references=["https://www.rfc-editor.org/rfc/rfc7208"],
                )
            )
        else:
            for note in analyze_spf(spf[0]):
                res.findings.append(
                    Finding(
                        title=f"Weak SPF policy for {domain}",
                        severity=Severity.LOW,
                        target=domain,
                        detection_module="",
                        confidence=Confidence.FIRM,
                        cwe="CWE-290",
                        description=note,
                        component=spf[0],
                        impact="A permissive SPF policy weakens protection against spoofing.",
                        remediation="End the SPF record with '-all' (hard fail).",
                        references=["https://www.rfc-editor.org/rfc/rfc7208"],
                    )
                )

        ctx.check_cancelled()
        dmarc = client.query(f"_dmarc.{domain}", "TXT")
        has_dmarc = dmarc.status == "ok" and any(
            txt_value(r).lower().startswith("v=dmarc1") for r in dmarc.rdata
        )
        if dmarc.status == "ok":
            res.add(*dmarc.records)
        if not has_dmarc:
            res.findings.append(
                Finding(
                    title=f"No DMARC record for {domain}",
                    severity=Severity.LOW,
                    target=domain,
                    detection_module="",
                    confidence=Confidence.FIRM,
                    cwe="CWE-290",
                    description=f"No DMARC policy was found at _dmarc.{domain}.",
                    impact="Without DMARC, SPF/DKIM failures are not enforced or reported, "
                    "easing spoofing of this domain.",
                    remediation="Publish a DMARC record, starting at 'p=none' with rua reporting "
                    "and progressing to 'p=reject'.",
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                )
            )
