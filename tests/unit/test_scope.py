from pathlib import Path

import pytest

from nxtsec.core.errors import ConfigError, ScopeViolation
from nxtsec.safety.scope import Scope
from nxtsec.targets import parse_target


@pytest.mark.parametrize(
    "raw",
    [
        "192.168.1.50",
        "10.10.10.0/25",
        "localhost",
        "127.0.0.1",
        "::1",
        "http://localhost:3000",
        "authorized.example.com",
        "https://authorized.example.com/a",
        "a.lab.example.com",
        "deep.a.lab.example.com",
        "fd00::5",
        "lab:dvwa",
        "file:/tmp/x",
    ],
)
def test_in_scope(scope, raw):
    assert scope.check(parse_target(raw)).allowed, raw


@pytest.mark.parametrize(
    "raw",
    [
        "8.8.8.8",
        "192.168.2.1",
        "10.10.0.0/16",
        "192.168.1.0/23",
        "example.com",
        "sub.authorized.example.com",
        "lab.example.com",
        "evilauthorized.example.com",
        "authorized.example.com.evil.net",
        "http://8.8.8.8/",
        "2001:db8::1",
    ],
)
def test_out_of_scope(scope, raw):
    assert not scope.check(parse_target(raw)).allowed, raw


def test_deny_wins(scope):
    assert not scope.check(parse_target("192.168.1.1")).allowed
    assert not scope.check(parse_target("secret.lab.example.com")).allowed
    # a range containing a denied host is refused as a whole
    assert not scope.check(parse_target("192.168.1.0/28")).allowed
    assert scope.check(parse_target("192.168.1.16/28")).allowed


def test_enforce_raises(scope):
    with pytest.raises(ScopeViolation):
        scope.enforce(parse_target("8.8.8.8"))


def test_empty_scope_refuses_everything():
    s = Scope.empty()
    for raw in ("127.0.0.1", "localhost", "10.0.0.1", "example.com"):
        assert not s.check(parse_target(raw)).allowed


def test_check_raw_handles_garbage(scope):
    d = scope.check_raw("not a host!")
    assert not d.allowed and "invalid target" in d.reason


@pytest.mark.parametrize("bad", [["10.0.0.0/99"], ["a b"], [""], [None], ["http://x/"]])
def test_invalid_scope_entries(bad):
    with pytest.raises(ConfigError):
        Scope(bad)


def test_load_yaml(tmp_path: Path):
    p = tmp_path / "scope.yaml"
    p.write_text("name: t\nallow: [10.0.0.0/8]\ndeny: [10.0.0.1]\n")
    s = Scope.load(p)
    assert s.name == "t"
    assert s.check_raw("10.2.3.4").allowed
    assert not s.check_raw("10.0.0.1").allowed


@pytest.mark.parametrize("text", ["allow: 10.0.0.0/8\n", "- a\n- b\n", "allow: [\n"])
def test_load_malformed(tmp_path: Path, text):
    p = tmp_path / "scope.yaml"
    p.write_text(text)
    with pytest.raises(ConfigError):
        Scope.load(p)


def test_load_missing(tmp_path: Path):
    with pytest.raises(ConfigError):
        Scope.load(tmp_path / "nope.yaml")
