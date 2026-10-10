"""dns.records: enumeration, relationships and mail-security findings (fake resolver)."""

import logging

import pytest

from nxtsec.core.models import Mode, Severity
from nxtsec.core.observations import DnsRecord
from nxtsec.events import EventBus
from nxtsec.modules.dns import records as mod
from nxtsec.modules.dns.records import DnsRecords, analyze_spf
from nxtsec.net.dns import DnsAnswer
from nxtsec.plugins import ModuleContext, Permission
from nxtsec.safety.scope import Scope
from nxtsec.targets import parse_target

SCOPE = Scope(["example.com", "*.example.com"], attestation="test")


class FakeClient:
    def __init__(self, answers):
        self._answers = answers
        self.nameservers = ["1.1.1.1"]
        self.queries = []

    def query(self, name, rtype):
        self.queries.append((name.lower(), rtype))
        key = (name.lower().rstrip("."), rtype)
        return self._answers.get(key, DnsAnswer(name, rtype, "nodata"))


def ok(name, rtype, *values, ttl=300):
    return DnsAnswer(
        name,
        rtype,
        "ok",
        records=[DnsRecord(name, rtype, v, ttl) for v in values],
        rdata=list(values),
    )


def ctx(options=None):
    return ModuleContext(
        "asm_t",
        Mode.REAL,
        SCOPE,
        frozenset({Permission.NETWORK_ACCESS}),
        logging.getLogger("t"),
        EventBus(),
        options=options or {},
        module_name="dns.records",
    )


def run_with(monkeypatch, answers, target="example.com"):
    client = FakeClient(answers)
    monkeypatch.setattr(mod, "_client", lambda c: client)
    result = DnsRecords().run(parse_target(target), ctx())
    return result, client


def test_enumerates_and_relates(monkeypatch):
    answers = {
        ("example.com", "A"): ok("example.com", "A", "93.184.216.34"),
        ("example.com", "MX"): ok("example.com", "MX", "10 mail.example.com."),
        ("example.com", "NS"): ok("example.com", "NS", "ns1.example.com."),
        ("example.com", "TXT"): ok("example.com", "TXT", "v=spf1 include:_spf.example.com -all"),
        ("_dmarc.example.com", "TXT"): ok(
            "_dmarc.example.com", "TXT", "v=DMARC1; p=reject; rua=mailto:d@example.com"
        ),
    }
    # rdata for TXT needs .strings for txt_value; use real-ish objects
    res, client = run_with(monkeypatch, _with_txt(answers))
    types = {o["type"] for o in res.observations}
    assert "dns.record" in types and "relation" in types
    rels = [
        (o["source"], o["relation"], o["target"])
        for o in res.observations
        if o["type"] == "relation"
    ]
    assert ("example.com", "mail_exchanger", "mail.example.com") in rels
    assert ("example.com", "name_server", "ns1.example.com") in rels
    # good SPF + DMARC => no mail-security findings
    assert res.findings == []


def test_missing_spf_and_dmarc(monkeypatch):
    res, _ = run_with(monkeypatch, {("example.com", "A"): ok("example.com", "A", "1.2.3.4")})
    titles = {f.title for f in res.findings}
    assert any("No SPF" in t for t in titles) and any("No DMARC" in t for t in titles)
    assert all(f.severity == Severity.LOW for f in res.findings)


def test_weak_spf(monkeypatch):
    answers = _with_txt({("example.com", "TXT"): ok("example.com", "TXT", "v=spf1 +all")})
    res, _ = run_with(monkeypatch, answers)
    assert any("Weak SPF" in f.title for f in res.findings)


def test_nxdomain_short_circuits(monkeypatch):
    answers = {("example.com", "A"): DnsAnswer("example.com", "A", "nxdomain")}
    res, client = run_with(monkeypatch, answers)
    assert any("NXDOMAIN" in e for e in res.errors)
    assert ("_dmarc.example.com", "TXT") not in client.queries  # stopped early


@pytest.mark.parametrize(
    ("record", "flagged"),
    [
        ("v=spf1 -all", False),
        ("v=spf1 ~all", False),
        ("v=spf1 +all", True),
        ("v=spf1 ?all", True),
        ("v=spf1 include:x.com", True),
    ],
)
def test_analyze_spf(record, flagged):
    assert bool(analyze_spf(record)) is flagged


def _with_txt(answers):
    """Attach objects exposing .strings so txt_value() works on rdata."""

    class Txt:
        def __init__(self, s):
            self.strings = [s.encode()]

        def to_text(self):
            return f'"{self.strings[0].decode()}"'

    fixed = {}
    for (name, rtype), ans in answers.items():
        if rtype == "TXT" and ans.status == "ok":
            ans.rdata = [Txt(r.value) for r in ans.records]
        fixed[(name, rtype)] = ans
    return fixed
