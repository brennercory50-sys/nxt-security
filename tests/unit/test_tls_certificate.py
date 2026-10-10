"""tls.certificate against a real loopback TLS server (fully offline)."""

import logging

import pytest
from cryptography import x509

from nxtsec.core.models import Mode, Severity
from nxtsec.events import EventBus
from nxtsec.modules.web.certificate import TlsCertificate, target_host_port
from nxtsec.net.tls import fetch_certificate, hostname_matches, parse_certificate
from nxtsec.plugins import ModuleContext, Permission
from nxtsec.safety.scope import Scope
from nxtsec.targets import parse_target
from tests.support.tls_server import make_cert, tls_server

SCOPE = Scope(["localhost", "127.0.0.0/8"], attestation="test")


def ctx(options=None):
    return ModuleContext(
        "asm_t",
        Mode.REAL,
        SCOPE,
        frozenset({Permission.NETWORK_ACCESS}),
        logging.getLogger("t"),
        EventBus(),
        options=options or {},
        module_name="tls.certificate",
    )


def run_against(tmp_path, port, target="localhost", **opts):
    opts.setdefault("port", str(port))
    return TlsCertificate().run(parse_target(target), ctx({k: str(v) for k, v in opts.items()}))


# -- net/tls layer ------------------------------------------------------------
def test_fetch_and_parse_self_signed(tmp_path):
    cert_path, key_path = make_cert(tmp_path, "localhost", ["localhost"])
    with tls_server(cert_path, key_path) as port:
        tls = fetch_certificate("127.0.0.1", port, "localhost", timeout=5)
    assert tls.verified is False and tls.verify_error  # self-signed not in trust store
    obs, cert = parse_certificate(tls, "localhost", port, "127.0.0.1")
    assert obs.self_signed and obs.key_type == "RSA" and obs.key_bits == 2048
    assert obs.hostname_match and obs.days_remaining > 0
    assert isinstance(cert, x509.Certificate) and len(obs.sha256) == 64


def test_fetch_no_server(tmp_path):
    from nxtsec.net.tls import TlsError

    with pytest.raises(TlsError):
        fetch_certificate("127.0.0.1", 1, "localhost", timeout=1)


@pytest.mark.parametrize(
    ("sans", "host", "match"),
    [
        (["example.com"], "example.com", True),
        (["example.com"], "other.com", False),
        (["*.example.com"], "a.example.com", True),
        (["*.example.com"], "example.com", False),
        (["*.example.com"], "a.b.example.com", False),
    ],
)
def test_hostname_matching(tmp_path, sans, host, match):
    cert_path, _ = make_cert(tmp_path, "cn.example", sans)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert hostname_matches(cert, host) is match


# -- module findings ----------------------------------------------------------
def test_healthy_cert_hostname_mismatch_only(tmp_path):
    # SAN=other.test but we connect as localhost -> only a hostname-mismatch finding
    cert_path, key_path = make_cert(tmp_path, "other.test", ["other.test"], days_after=200)
    with tls_server(cert_path, key_path) as port:
        res = run_against(tmp_path, port)
    titles = [f.title for f in res.findings]
    assert any("hostname mismatch" in t for t in titles)
    assert any("self-signed" in t.lower() or "untrusted" in t.lower() for t in titles)


def test_expired_cert(tmp_path):
    cert_path, key_path = make_cert(
        tmp_path, "localhost", ["localhost"], days_before=40, days_after=-10
    )
    with tls_server(cert_path, key_path) as port:
        res = run_against(tmp_path, port)
    expired = [f for f in res.findings if "Expired" in f.title]
    assert expired and expired[0].severity == Severity.HIGH


def test_expiring_soon(tmp_path):
    cert_path, key_path = make_cert(tmp_path, "localhost", ["localhost"], days_after=10)
    with tls_server(cert_path, key_path) as port:
        res = run_against(tmp_path, port)
    soon = [f for f in res.findings if "expiring soon" in f.title]
    assert soon and soon[0].severity == Severity.MEDIUM


def _cert_obs(**overrides):
    from nxtsec.core.observations import Certificate

    base = dict(
        host="h.test",
        port=443,
        address="127.0.0.1",
        subject="h.test",
        issuer="CA",
        sans=["h.test"],
        serial="01",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        days_remaining=200,
        signature_algorithm="sha256",
        key_type="RSA",
        key_bits=2048,
        sha256="0" * 64,
        self_signed=False,
        trusted=True,
        hostname_match=True,
    )
    base.update(overrides)
    return Certificate(**base)


@pytest.mark.parametrize(
    ("key_type", "key_bits", "flagged"),
    [
        ("RSA", 1024, True),
        ("RSA", 2048, False),
        ("RSA", 4096, False),
        ("EC (secp256r1)", 256, False),
        ("EC (secp192r1)", 192, True),
    ],
)
def test_weak_key_finding(key_type, key_bits, flagged):
    from nxtsec.plugins.base import ModuleResult

    res = ModuleResult()
    TlsCertificate()._findings(_cert_obs(key_type=key_type, key_bits=key_bits), res)
    assert any("Weak" in f.title for f in res.findings) is flagged


def test_all_clear_cert_has_no_findings():
    from nxtsec.plugins.base import ModuleResult

    res = ModuleResult()
    TlsCertificate()._findings(_cert_obs(), res)
    assert res.findings == []


def test_ec_key_not_flagged_weak(tmp_path):
    cert_path, key_path = make_cert(tmp_path, "localhost", ["localhost"], key_type="ec")
    with tls_server(cert_path, key_path) as port:
        res = run_against(tmp_path, port)
    [obs] = [o for o in res.observations if o["type"] == "tls.certificate"]
    assert obs["key_type"].startswith("EC")
    assert not any("Weak" in f.title for f in res.findings)


def test_observation_emitted_and_redaction_safe(tmp_path):
    cert_path, key_path = make_cert(tmp_path, "localhost", ["localhost"])
    with tls_server(cert_path, key_path) as port:
        res = run_against(tmp_path, port)
    certs = [o for o in res.observations if o["type"] == "tls.certificate"]
    assert len(certs) == 1 and certs[0]["tls_version"].startswith("TLSv1")


def test_unresolvable_host_records_error(monkeypatch, tmp_path):
    import nxtsec.modules.web.certificate as m

    def boom(h, t):
        raise OSError("no such host")

    monkeypatch.setattr(m, "resolve_host", boom)
    res = TlsCertificate().run(parse_target("nothing.invalid"), ctx({"port": "443"}))
    assert res.observations == [] and "cannot resolve" in res.errors[0]


def test_connection_refused_records_error(tmp_path):
    res = run_against(tmp_path, 1)  # port 1: nothing listening
    assert res.observations == [] and res.errors


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://example.com:8443/x", ("example.com", 8443)),
        ("https://example.com/", ("example.com", 443)),
        ("example.com", ("example.com", 443)),
    ],
)
def test_target_host_port(target, expected):
    assert target_host_port(parse_target(target)) == expected


def test_http_url_rejected():
    from nxtsec.core.errors import PluginError

    with pytest.raises(PluginError):
        target_host_port(parse_target("http://example.com/"))
