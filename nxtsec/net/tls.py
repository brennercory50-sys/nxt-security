"""TLS connection and certificate parsing for authorized target inspection.

``fetch_certificate`` opens a TLS connection to a specific address, completes
the handshake with SNI set to the hostname, and returns the leaf certificate
(DER) plus the negotiated protocol version and cipher. Verification is
attempted against the system trust store; if it fails the handshake is
repeated without verification so the certificate can still be examined, and
the ``verified`` flag records the outcome with the reason.

``parse_certificate`` turns the DER bytes into a normalized
:class:`~nxtsec.core.observations.Certificate`, and ``hostname_matches``
checks a presented certificate against the expected name.

Only certificate inspection lives here; it does not send application data.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from nxtsec.core.errors import NxtSecError
from nxtsec.core.observations import Certificate


class TlsError(NxtSecError):
    """A TLS connection could not be established at all."""


@dataclass
class TlsResult:
    der: bytes
    tls_version: str | None
    cipher: str | None
    verified: bool
    verify_error: str | None


def fetch_certificate(
    address: str, port: int, server_name: str, *, timeout: float = 10.0
) -> TlsResult:
    """Return the leaf certificate presented by ``address:port`` for ``server_name``."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    verified = True
    verify_error: str | None = None
    ctx = ssl.create_default_context()
    try:
        der, version, cipher = _handshake(ctx, address, port, server_name, family, timeout)
    except ssl.SSLCertVerificationError as exc:
        verified, verify_error = False, exc.verify_message or str(exc)
        unverified = ssl._create_unverified_context()  # noqa: S323 - deliberate: inspect anyway
        try:
            der, version, cipher = _handshake(
                unverified, address, port, server_name, family, timeout
            )
        except (OSError, ssl.SSLError) as exc2:
            raise TlsError(f"TLS handshake with {address}:{port} failed: {exc2}") from exc2
    except (OSError, ssl.SSLError) as exc:
        raise TlsError(f"TLS handshake with {address}:{port} failed: {exc}") from exc
    return TlsResult(der, version, cipher, verified, verify_error)


def _handshake(
    ctx: ssl.SSLContext,
    address: str,
    port: int,
    server_name: str,
    family: int,
    timeout: float,
) -> tuple[bytes, str | None, str | None]:
    with socket.socket(family, socket.SOCK_STREAM) as raw:
        raw.settimeout(timeout)
        raw.connect((address, port))
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise TlsError(f"{address}:{port} presented no certificate")
            return der, tls.version(), (tls.cipher() or (None,))[0]


def _name(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [str(n) for n in ext.value.get_values_for_type(x509.DNSName)]


def _key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(pub).__name__, getattr(pub, "key_size", None)


def hostname_matches(cert: x509.Certificate, hostname: str) -> bool:
    """RFC 6125 name check: SANs (with left-most-label wildcards), else CN fallback."""
    host = hostname.rstrip(".").lower()
    names = _sans(cert)
    if not names:
        cn = _name(cert.subject, NameOID.COMMON_NAME)
        names = [cn] if cn else []
    for raw in names:
        pattern = raw.rstrip(".").lower()
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            if host.endswith(suffix) and host.count(".") == pattern.count("."):
                return True
        elif host == pattern:
            return True
    return False


def parse_certificate(
    result: TlsResult, host: str, port: int, address: str
) -> tuple[Certificate, x509.Certificate]:
    from datetime import datetime, timezone

    cert = x509.load_der_x509_certificate(result.der)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_remaining = (not_after - datetime.now(timezone.utc)).days
    key_type, key_bits = _key_info(cert)
    try:
        sig_alg = cert.signature_algorithm_oid._name
    except Exception:  # noqa: BLE001 - some algorithms have no friendly name
        sig_alg = None
    subject_cn = _name(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _name(cert.issuer, NameOID.COMMON_NAME)
    self_signed = cert.subject == cert.issuer

    observation = Certificate(
        host=host,
        port=port,
        address=address,
        subject=subject_cn or cert.subject.rfc4514_string(),
        issuer=issuer_cn or cert.issuer.rfc4514_string(),
        sans=_sans(cert),
        serial=format(cert.serial_number, "x"),
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        days_remaining=days_remaining,
        signature_algorithm=sig_alg,
        key_type=key_type,
        key_bits=key_bits,
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
        self_signed=self_signed,
        trusted=result.verified,
        hostname_match=hostname_matches(cert, host),
        tls_version=result.tls_version,
        cipher=result.cipher,
        trust_error=result.verify_error,
    )
    return observation, cert
