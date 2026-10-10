"""DnsClient: configuration and answer normalization against a fake dnspython resolver."""

import types

import pytest

import nxtsec.net.dns as dnsmod
from nxtsec.net.dns import DnsClient, DnsError


class FakeRRItem:
    def __init__(self, text, strings=None):
        self._text = text
        if strings is not None:
            self.strings = strings

    def to_text(self):
        return self._text


class FakeRRSet:
    def __init__(self, name, ttl, items):
        self.name = types.SimpleNamespace(to_text=lambda: name)
        self.ttl = ttl
        self._items = items

    def __iter__(self):
        return iter(self._items)


class FakeAnswer:
    def __init__(self, rrset):
        self.rrset = rrset


class FakeResolver:
    def __init__(self, configure=True):
        self.nameservers = ["9.9.9.9"] if configure else []
        self.port = 53
        self.timeout = self.lifetime = None
        self.script = {}

    def resolve(self, qname, rtype, raise_on_no_answer=True):
        key = (str(qname).rstrip(".").lower(), rtype)
        outcome = self.script.get(key)
        if outcome is None:
            return FakeAnswer(None)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeAnswer(outcome)


@pytest.fixture
def patched(monkeypatch):
    holder = {}

    def factory(configure=True):
        r = FakeResolver(configure)
        holder["resolver"] = r
        return r

    monkeypatch.setattr(dnsmod.dns.resolver, "Resolver", factory)
    return holder


def test_explicit_nameservers_override(patched):
    c = DnsClient(["1.1.1.1", "8.8.8.8"], timeout=3)
    assert c.nameservers == ["1.1.1.1", "8.8.8.8"]
    assert patched["resolver"].timeout == 3 and patched["resolver"].lifetime == 3


def test_a_record_normalized(patched):
    c = DnsClient(["1.1.1.1"])
    patched["resolver"].script[("example.com", "A")] = FakeRRSet(
        "example.com.", 60, [FakeRRItem("93.184.216.34")]
    )
    ans = c.query("Example.COM.", "A")
    assert ans.status == "ok"
    assert ans.records[0].name == "example.com" and ans.records[0].ttl == 60
    assert ans.records[0].value == "93.184.216.34"


def test_txt_concatenates_strings(patched):
    c = DnsClient(["1.1.1.1"])
    patched["resolver"].script[("example.com", "TXT")] = FakeRRSet(
        "example.com.", 300, [FakeRRItem('"v=spf1" " -all"', strings=[b"v=spf1", b" -all"])]
    )
    ans = c.query("example.com", "TXT")
    assert ans.records[0].value == "v=spf1 -all"


def test_trailing_dot_stripped_for_cname(patched):
    c = DnsClient(["1.1.1.1"])
    patched["resolver"].script[("www.example.com", "CNAME")] = FakeRRSet(
        "www.example.com.", 300, [FakeRRItem("example.com.")]
    )
    assert c.query("www.example.com", "CNAME").records[0].value == "example.com"


def test_status_mapping(patched):
    import dns.resolver as r

    c = DnsClient(["1.1.1.1"])
    res = patched["resolver"]
    res.script[("none.example", "A")] = r.NXDOMAIN()
    assert c.query("none.example", "A").status == "nxdomain"
    assert c.query("nodata.example", "A").status == "nodata"  # no script => rrset None


def test_unsupported_type(patched):
    with pytest.raises(DnsError):
        DnsClient(["1.1.1.1"]).query("example.com", "WKS")


def test_reverse_sets_name(patched):
    c = DnsClient(["1.1.1.1"])
    patched["resolver"].script[("34.216.184.93.in-addr.arpa", "PTR")] = FakeRRSet(
        "34.216.184.93.in-addr.arpa.", 300, [FakeRRItem("example.com.")]
    )
    ans = c.reverse("93.184.216.34")
    assert ans.name == "93.184.216.34" and ans.records[0].value == "example.com"
