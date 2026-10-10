"""ip.info: offline classification and PTR lookups."""

import ipaddress
import logging

import pytest

import nxtsec.modules.network.ip_info as mod
from nxtsec.core.models import Mode
from nxtsec.core.observations import DnsRecord
from nxtsec.events import EventBus
from nxtsec.modules.network.ip_info import IpInfoModule, classify
from nxtsec.net.dns import DnsAnswer
from nxtsec.plugins import ModuleContext, Permission
from nxtsec.safety.scope import Scope
from nxtsec.targets import parse_target

SCOPE = Scope(["192.168.0.0/16", "8.8.8.8", "example.com"], attestation="test")


@pytest.mark.parametrize(
    ("addr", "expect"),
    [
        ("8.8.8.8", "global"),
        ("192.168.1.1", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link-local"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"),
        ("::1", "loopback"),
        ("2606:4700::1", "global"),
        ("fe80::1", "link-local"),
    ],
)
def test_classify(addr, expect):
    assert classify(ipaddress.ip_address(addr)) == expect


def ctx():
    return ModuleContext(
        "asm_t",
        Mode.REAL,
        SCOPE,
        frozenset({Permission.NETWORK_ACCESS}),
        logging.getLogger("t"),
        EventBus(),
        module_name="ip.info",
    )


class FakePtr:
    nameservers = ["1.1.1.1"]

    def __init__(self, mapping):
        self._m = mapping

    def reverse(self, addr):
        names = self._m.get(addr)
        if names is None:
            return DnsAnswer(addr, "PTR", "nodata")
        return DnsAnswer(addr, "PTR", "ok", records=[DnsRecord(addr, "PTR", n) for n in names])


def test_ip_target_with_ptr(monkeypatch):
    monkeypatch.setattr(
        mod, "DnsClient", lambda ns, timeout=5: FakePtr({"8.8.8.8": ["dns.google"]})
    )
    res = IpInfoModule().run(parse_target("8.8.8.8"), ctx())
    [obs] = res.observations
    assert obs["classification"] == "global" and obs["ptr"] == ["dns.google"]


def test_hostname_resolved_then_classified(monkeypatch):
    monkeypatch.setattr(mod, "resolve_host", lambda h, t: ["192.168.1.50"])
    monkeypatch.setattr(mod, "DnsClient", lambda ns, timeout=5: FakePtr({}))
    res = IpInfoModule().run(parse_target("example.com"), ctx())
    assert res.observations[0]["classification"] == "private"


def test_unresolvable(monkeypatch):
    def boom(h, t):
        raise OSError("no such host")

    monkeypatch.setattr(mod, "resolve_host", boom)
    res = IpInfoModule().run(parse_target("example.com"), ctx())
    assert res.observations == [] and "cannot resolve" in res.errors[0]
