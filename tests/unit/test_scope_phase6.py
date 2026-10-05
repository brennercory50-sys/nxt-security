"""Phase 6: expiry, per-rule metadata, fingerprints, resolution guard, config hardening."""

from datetime import datetime, timedelta, timezone

import pytest

from nxtsec.core.errors import ConfigError
from nxtsec.safety.scope import Scope, parse_expiry
from nxtsec.targets import parse_target

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def test_parse_expiry_forms():
    from datetime import date

    assert parse_expiry("2026-12-31") == datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert parse_expiry(date(2026, 12, 31)).hour == 23
    assert parse_expiry("2026-12-31T10:00:00Z").hour == 10
    assert parse_expiry(None) is None
    with pytest.raises(ConfigError):
        parse_expiry("next tuesday")
    with pytest.raises(ConfigError):
        parse_expiry(12345)


def test_scope_level_expiry_refuses_everything_network():
    s = Scope(["10.0.0.0/8"], expires="2026-10-01", attestation="x")
    assert s.is_expired(NOW)
    d = s.check(parse_target("10.1.1.1"), NOW)
    assert not d.allowed and "expired" in d.reason
    # files and labs are not network-scoped
    assert s.check(parse_target("file:/x"), NOW).allowed
    # before expiry it worked
    assert s.check(parse_target("10.1.1.1"), NOW - timedelta(days=10)).allowed


def test_per_rule_expiry_and_note():
    s = Scope(
        [
            "192.168.1.0/24",
            {"target": "10.10.10.0/24", "expires": "2026-10-04", "note": "test window"},
            {"target": "10.20.0.0/16", "expires": "2026-10-30"},
        ]
    )
    assert s.check(parse_target("192.168.1.5"), NOW).allowed
    assert not s.check(parse_target("10.10.10.5"), NOW).allowed  # expired yesterday
    assert s.check(parse_target("10.20.1.1"), NOW).allowed
    assert s.allow_rules[1].note == "test window"


def test_expired_deny_rule_no_longer_denies():
    s = Scope(["10.0.0.0/8"], [{"target": "10.0.0.1", "expires": "2026-01-01"}])
    assert s.check(parse_target("10.0.0.1"), NOW).allowed


def test_expiring_within():
    s = Scope(
        [{"target": "10.0.0.0/24", "expires": "2026-10-08"}, "10.1.0.0/24"],
        expires="2026-10-09",
    )
    soon = s.expiring_within(timedelta(days=7), NOW)
    assert len(soon) == 2 and any("10.0.0.0/24" in x for x in soon)
    assert s.expiring_within(timedelta(days=1), NOW) == []


def test_fingerprint_stable_and_sensitive():
    a = Scope(["10.0.0.0/8"], ["10.0.0.1"], name="n", attestation="ok")
    b = Scope(["10.0.0.0/8"], ["10.0.0.1"], name="n", attestation="ok")
    c = Scope(["10.0.0.0/8"], [], name="n", attestation="ok")
    d = Scope(["10.0.0.0/8"], ["10.0.0.1"], name="n", attestation="other")
    assert a.fingerprint == b.fingerprint
    assert len({a.fingerprint, c.fingerprint, d.fingerprint}) == 3


@pytest.mark.parametrize(
    "bad",
    [
        ["0.0.0.0/0"],
        ["::/0"],
        ["10.0.0.0/7"],
        ["*.com"],
        ["*."],
        [{"target": "10.0.0.0/8", "expire": "2026-01-01"}],  # typo'd key
        [{"note": "missing target"}],
        [{"target": "10.0.0.0/8", "expires": "soon"}],
    ],
)
def test_rejected_rules(bad):
    with pytest.raises(ConfigError):
        Scope(bad)


def test_broad_deny_is_fine():
    s = Scope(["10.0.0.0/8"], ["0.0.0.0/1"])
    assert not s.check(parse_target("10.0.0.1"), NOW).allowed


def test_unknown_top_level_key():
    with pytest.raises(ConfigError, match="unknown keys"):
        Scope.from_dict({"alow": ["10.0.0.0/8"]})
    with pytest.raises(ConfigError):
        Scope.from_dict({"allow": [], "operator_attestation": 5})


def test_blank_attestation_is_none():
    assert Scope([], attestation="   ").attestation is None


def test_loopback_deny_blocks_loopback_cidr():
    s = Scope(["127.0.0.0/8"], ["localhost"])
    assert not s.check(parse_target("127.0.0.0/30"), NOW).allowed


class TestResolution:
    s = Scope(
        ["app.example.com", "nas.home", "192.168.1.0/24", "localhost"],
        ["192.168.1.1"],
        attestation="x",
    )

    def test_public_address_ok(self):
        assert self.s.check_resolution("app.example.com", ["93.184.216.34"], NOW).allowed

    def test_denied_address_refused(self):
        d = self.s.check_resolution("app.example.com", ["192.168.1.1"], NOW)
        assert not d.allowed and "denied" in d.reason

    @pytest.mark.parametrize(
        "addr", ["10.0.0.5", "169.254.169.254", "127.0.0.1", "fd00::1", "0.0.0.0", "224.0.0.1"]
    )
    def test_internal_address_not_in_scope_refused(self, addr):
        s = Scope(["app.example.com"], attestation="x")
        d = s.check_resolution("app.example.com", [addr], NOW)
        assert not d.allowed and "internal address" in d.reason

    def test_internal_address_in_scope_ok(self):
        assert self.s.check_resolution("nas.home", ["192.168.1.20"], NOW).allowed
        assert self.s.check_resolution("localhost", ["127.0.0.1", "::1"], NOW).allowed

    def test_one_bad_address_poisons_all(self):
        d = self.s.check_resolution("app.example.com", ["93.184.216.34", "10.9.9.9"], NOW)
        assert not d.allowed

    def test_no_addresses_and_garbage(self):
        assert not self.s.check_resolution("x", [], NOW).allowed
        assert not self.s.check_resolution("x", ["not-an-ip"], NOW).allowed

    def test_ipv6_zone_id_stripped(self):
        s = Scope(["fe80::/10"], attestation="x")
        assert s.check_resolution("h", ["fe80::1%eth0"], NOW).allowed


def test_describe_shape():
    s = Scope([{"target": "10.0.0.0/8", "note": "n"}], name="d", attestation="a")
    d = s.describe()
    assert d["allow"][0] == {"target": "10.0.0.0/8", "expires": None, "note": "n"}
    assert d["fingerprint"] == s.fingerprint
