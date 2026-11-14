"""``network.nmap``: authorized port/service scan via the nmap integration.

Runs a non-destructive nmap profile against a single in-scope address and
normalizes the XML into HostStatus / PortState / Service observations. Nmap is
invoked through the safe runner (argv list, resolved binary, timeout); the
target address is validated and scope-checked before the scan. If nmap is not
installed the module records an error instead of failing the assessment.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory

from nxtsec.core.errors import CommandError, PluginError, ScopeViolation
from nxtsec.core.models import Target, TargetType
from nxtsec.integrations.nmap import (
    DEFAULT_PROFILE,
    PROFILES,
    NmapError,
    build_argv,
    parse_xml,
)
from nxtsec.net.resolve import LookupTimeout, is_ip, resolve_host
from nxtsec.plugins.base import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    RiskLevel,
    option_lookup,
)
from nxtsec.safety.execution import resolve_binary, run_command
from nxtsec.safety.redaction import redact

NAME = "network.nmap"
_PORTS_MAXLEN = 256


def _validate_ports(spec: str) -> str:
    """Accept nmap -p syntax limited to digits, commas and hyphens (no scripts/args)."""
    spec = spec.strip()
    if not spec or len(spec) > _PORTS_MAXLEN:
        raise PluginError("invalid ports specification")
    allowed = set("0123456789,-")
    if any(c not in allowed for c in spec):
        raise PluginError("ports may contain only digits, commas and hyphens")
    return spec


class NmapScan(Plugin):
    manifest = PluginManifest(
        name=NAME,
        version="0.1.0",
        description="Authorized port/service scan (nmap connect-scan profiles)",
        category="network",
        author="NXT-Security",
        permissions=frozenset({Permission.NETWORK_ACCESS, Permission.EXEC_TOOLS}),
        risk_level=RiskLevel.MEDIUM,
        target_types=frozenset(
            {TargetType.IPV4, TargetType.IPV6, TargetType.DOMAIN, TargetType.HOSTNAME}
        ),
        requires_tools=("nmap",),
    )

    @classmethod
    def validate_options(cls, options: Mapping[str, str]) -> None:
        profile = option_lookup(options, NAME, "profile")
        if profile is not None and profile not in PROFILES:
            raise PluginError(f"unknown profile {profile!r}; choose from {sorted(PROFILES)}")
        ports = option_lookup(options, NAME, "ports")
        if ports is not None:
            _validate_ports(ports)

    def run(self, target: Target | None, ctx: ModuleContext) -> ModuleResult:
        ctx.require(Permission.NETWORK_ACCESS)
        ctx.require(Permission.EXEC_TOOLS)
        assert target is not None and target.host is not None
        res = ModuleResult()

        nmap_path = ctx.setting("tools.nmap.path")
        if resolve_binary("nmap", nmap_path) is None:
            res.errors.append(
                "nmap is not installed or not on PATH; install it or set tools.nmap.path "
                "(see `nxtsec tools info nmap`)"
            )
            return res

        host = target.host
        if is_ip(host):
            address = host
        else:
            try:
                addresses = resolve_host(host, timeout=10.0)
            except (OSError, LookupTimeout) as exc:
                res.errors.append(f"cannot resolve {host}: {exc}")
                return res
            decision = ctx.scope.check_resolution(host, addresses)
            if not decision.allowed:
                raise ScopeViolation(decision.reason)
            address = addresses[0]

        profile = ctx.option("profile", DEFAULT_PROFILE) or DEFAULT_PROFILE
        ports = ctx.option("ports")
        if ports:
            ports = _validate_ports(ports)
        timeout = ctx.option_float("timeout", 300.0, 5.0, 3600.0)

        ctx.check_cancelled()
        with TemporaryDirectory(prefix="nxtsec-nmap-") as tmp:
            xml_path = str(Path(tmp) / "scan.xml")
            try:
                argv = build_argv(address, profile=profile, ports=ports, xml_path=xml_path)
            except NmapError as exc:
                raise PluginError(str(exc)) from exc
            res.commands.append(redact(" ".join(argv)))
            try:
                proc = run_command(argv, timeout=timeout, binary_path=nmap_path)
            except CommandError as exc:
                res.errors.append(f"nmap failed to run: {exc}")
                return res
            try:
                xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                res.errors.append(
                    f"nmap produced no XML output: {exc} (stderr: {proc.stderr[:200]})"
                )
                return res

        try:
            parsed = parse_xml(xml_text)
        except NmapError as exc:
            res.errors.append(str(exc))
            return res

        ctx.save_evidence(xml_text.encode("utf-8"), "nmap.xml", "scan_xml", "nmap XML output")
        res.add(*parsed.all_observations())
        open_ports = sum(p.state == "open" for p in parsed.ports)
        ctx.logger.info(
            f"nmap {profile} on {address}: {len(parsed.hosts)} host(s), {open_ports} open port(s)"
        )
        if not proc.ok and not parsed.hosts:
            res.errors.append(f"nmap exited {proc.returncode}: {redact(proc.stderr[:200])}")
        return res
