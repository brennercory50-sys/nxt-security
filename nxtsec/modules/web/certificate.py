"""``tls.certificate``: inspect the X.509 certificate presented by a host.

Connects to the target's scope-checked address, reads the leaf certificate,
and raises findings an owner needs about their own endpoint: expired or
soon-to-expire certificate, untrusted/self-signed chain, hostname mismatch,
and weak key size. It performs certificate inspection only.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from nxtsec.core.errors import PluginError, ScopeViolation
from nxtsec.core.models import Confidence, Finding, Severity, Target, TargetType
from nxtsec.net.resolve import LookupTimeout, is_ip, resolve_host
from nxtsec.net.tls import TlsError, fetch_certificate, parse_certificate
from nxtsec.plugins.base import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    RiskLevel,
    option_lookup,
    parse_int_option,
)

NAME = "tls.certificate"
EXPIRY_WARN_DAYS = 30
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256


def target_host_port(target: Target) -> tuple[str, int]:
    if target.type == TargetType.URL:
        parts = urlsplit(target.value)
        if parts.scheme != "https":
            raise PluginError("tls.certificate requires an https:// URL or a host")
        assert parts.hostname is not None
        return parts.hostname, parts.port or 443
    assert target.host is not None
    return target.host, 443


class TlsCertificate(Plugin):
    manifest = PluginManifest(
        name=NAME,
        version="0.1.0",
        description="Inspect a host's TLS certificate (expiry, trust, hostname, key strength)",
        category="web",
        author="NXT-Security",
        permissions=frozenset({Permission.NETWORK_ACCESS}),
        risk_level=RiskLevel.LOW,
        target_types=frozenset(
            {
                TargetType.DOMAIN,
                TargetType.HOSTNAME,
                TargetType.IPV4,
                TargetType.IPV6,
                TargetType.URL,
            }
        ),
    )

    @classmethod
    def validate_options(cls, options):  # type: ignore[no-untyped-def]
        p = option_lookup(options, NAME, "port")
        if p is not None:
            parse_int_option(p, "port", 443, 1, 65535)

    def run(self, target: Target | None, ctx: ModuleContext) -> ModuleResult:
        ctx.require(Permission.NETWORK_ACCESS)
        assert target is not None
        host, default_port = target_host_port(target)
        port = ctx.option_int("port", default_port, 1, 65535)
        timeout = ctx.option_float("timeout", 10.0, 1.0, 60.0)
        res = ModuleResult()

        if is_ip(host):
            address = host
        else:
            try:
                addresses = resolve_host(host, timeout)
            except (OSError, LookupTimeout) as exc:
                res.errors.append(f"cannot resolve {host}: {exc}")
                return res
            decision = ctx.scope.check_resolution(host, addresses)
            if not decision.allowed:
                raise ScopeViolation(decision.reason)
            address = addresses[0]

        ctx.check_cancelled()
        try:
            tls = fetch_certificate(address, port, host, timeout=timeout)
        except TlsError as exc:
            res.errors.append(str(exc))
            return res

        observation, _cert = parse_certificate(tls, host, port, address)
        res.add(observation)
        self._findings(observation, res)
        ctx.logger.info(
            f"{host}:{port} cert expires in {observation.days_remaining}d, "
            f"trusted={observation.trusted}"
        )
        return res

    def _findings(self, c, res: ModuleResult) -> None:  # type: ignore[no-untyped-def]
        where = f"{c.host}:{c.port}"
        refs = ["https://www.rfc-editor.org/rfc/rfc5280"]

        if c.days_remaining < 0:
            res.findings.append(
                Finding(
                    title=f"Expired TLS certificate on {where}",
                    severity=Severity.HIGH,
                    target=where,
                    detection_module="",
                    confidence=Confidence.CONFIRMED,
                    cwe="CWE-298",
                    component=c.subject,
                    description=f"The certificate expired on {c.not_after} "
                    f"({-c.days_remaining} days ago).",
                    impact="Clients see certificate errors; the endpoint is effectively unusable "
                    "over TLS and users may be trained to bypass warnings.",
                    remediation="Renew and deploy a current certificate; automate renewal.",
                    references=refs,
                )
            )
        elif c.days_remaining <= EXPIRY_WARN_DAYS:
            res.findings.append(
                Finding(
                    title=f"TLS certificate expiring soon on {where}",
                    severity=Severity.MEDIUM,
                    target=where,
                    detection_module="",
                    confidence=Confidence.CONFIRMED,
                    cwe="CWE-298",
                    component=c.subject,
                    description=f"The certificate expires on {c.not_after} "
                    f"(in {c.days_remaining} days).",
                    impact="If it lapses, clients will see certificate errors.",
                    remediation="Renew the certificate and automate future renewals.",
                    references=refs,
                )
            )

        if not c.trusted:
            kind = "self-signed" if c.self_signed else "untrusted"
            res.findings.append(
                Finding(
                    title=f"{kind.capitalize()} TLS certificate on {where}",
                    severity=Severity.MEDIUM,
                    target=where,
                    detection_module="",
                    confidence=Confidence.CONFIRMED,
                    cwe="CWE-295",
                    component=c.issuer,
                    description=f"The certificate chain did not verify against the system trust "
                    f"store ({c.trust_error}).",
                    impact="Clients cannot establish trust without manual exceptions, masking "
                    "real man-in-the-middle conditions.",
                    remediation="Install a certificate from a trusted CA with the full chain.",
                    references=refs,
                )
            )

        if not c.hostname_match:
            res.findings.append(
                Finding(
                    title=f"TLS certificate hostname mismatch on {where}",
                    severity=Severity.MEDIUM,
                    target=where,
                    detection_module="",
                    confidence=Confidence.CONFIRMED,
                    cwe="CWE-297",
                    component=c.subject,
                    description=f"'{c.host}' is not covered by the certificate "
                    f"(subject {c.subject}, SANs {c.sans}).",
                    impact="Strict clients reject the connection; it indicates a misissued or "
                    "misdeployed certificate.",
                    remediation="Deploy a certificate whose SANs include this hostname.",
                    references=refs,
                )
            )

        weak = (c.key_type == "RSA" and (c.key_bits or 0) < MIN_RSA_BITS) or (
            c.key_type.startswith("EC") and (c.key_bits or 0) < MIN_EC_BITS
        )
        if weak:
            res.findings.append(
                Finding(
                    title=f"Weak TLS certificate key on {where}",
                    severity=Severity.MEDIUM,
                    target=where,
                    detection_module="",
                    confidence=Confidence.FIRM,
                    cwe="CWE-326",
                    component=f"{c.key_type} {c.key_bits}",
                    description=f"The certificate uses a {c.key_type} key of {c.key_bits} bits.",
                    impact="Keys below current minimums are more vulnerable to cryptanalysis.",
                    remediation="Reissue with at least RSA-2048 or a 256-bit elliptic-curve key.",
                    references=["https://www.rfc-editor.org/rfc/rfc5280"],
                )
            )
