import pytest

from nxtsec.core.errors import TargetError
from nxtsec.core.models import TargetType
from nxtsec.targets import parse_target


@pytest.mark.parametrize(
    ("raw", "ttype", "host"),
    [
        ("192.168.1.10", TargetType.IPV4, "192.168.1.10"),
        ("::1", TargetType.IPV6, "::1"),
        ("[fe80::1]", TargetType.IPV6, "fe80::1"),
        ("10.0.0.0/24", TargetType.CIDR, "10.0.0.0/24"),
        ("10.0.0.5/24", TargetType.CIDR, "10.0.0.0/24"),
        ("Example.COM.", TargetType.DOMAIN, "example.com"),
        ("localhost", TargetType.HOSTNAME, "localhost"),
        ("https://Authorized.example.com:8443/x?y=1", TargetType.URL, "authorized.example.com"),
        ("http://[::1]:8080/", TargetType.URL, "::1"),
    ],
)
def test_parse_valid(raw, ttype, host):
    t = parse_target(raw)
    assert t.type == ttype
    assert t.host == host


def test_parse_lab_and_file():
    assert parse_target("lab:dvwa").type == TargetType.LAB
    assert parse_target("file:./x.bin").type == TargetType.FILE
    with pytest.raises(TargetError):
        parse_target("file:./x", allow_files=False)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "a" * 3000,
        "bad host",
        "-bad.com",
        "exa_mple.com",
        "ftp://example.com",
        "http://user:pw@example.com",
        "http://",
        "10.0.0.0/33",
        "foo\x00bar",
        "line\nbreak",
        "lab:Bad Name",
        "http://example.com:99999/",
        "file:",
        "a..b",
    ],
)
def test_parse_invalid(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


def test_non_string():
    with pytest.raises(TargetError):
        parse_target(123)  # type: ignore[arg-type]
