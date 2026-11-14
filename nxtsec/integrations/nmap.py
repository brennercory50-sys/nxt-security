"""Nmap integration: safe argv construction and XML result parsing.

The parser is the testable core; it turns ``nmap -oX`` output into normalized
``HostStatus`` / ``PortState`` / ``Service`` observations. Argv is always a
list (never a shell string), options come from a fixed vocabulary, and the
target address is passed as the final argument after validation elsewhere.

Scan XML is produced by the nmap process this tool runs and written to a file
we control; it is parsed with the standard library parser, which does not
resolve external entities.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET  # noqa: S405 - parsing our own tool's output, no external entities
from dataclasses import dataclass, field

from nxtsec.core.errors import NxtSecError
from nxtsec.core.observations import HostStatus, PortState, Service

# Named, non-destructive scan profiles. Each maps to a fixed, reviewed argv.
# Nothing here enables intrusive NSE scripts, OS fingerprinting floods, or
# aggressive timing beyond T4.
PROFILES: dict[str, list[str]] = {
    "connect": ["-sT", "-T4"],  # TCP connect scan (no raw sockets needed)
    "top-ports": ["-sT", "-T4", "--top-ports", "100"],
    "service": ["-sT", "-sV", "-T4"],  # service/version detection
    "quick": ["-sT", "-T4", "-F"],  # fast: ~100 common ports
}
DEFAULT_PROFILE = "top-ports"


class NmapError(NxtSecError):
    """Nmap output could not be parsed."""


@dataclass
class NmapResult:
    hosts: list[HostStatus] = field(default_factory=list)
    ports: list[PortState] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)

    def all_observations(self) -> list[HostStatus | PortState | Service]:
        return [*self.hosts, *self.ports, *self.services]


def build_argv(address: str, *, profile: str, ports: str | None, xml_path: str) -> list[str]:
    """Construct the nmap argv for a single target. ``nmap`` itself is prepended by the runner."""
    if profile not in PROFILES:
        raise NmapError(f"unknown scan profile {profile!r}; choose from {sorted(PROFILES)}")
    argv = ["nmap", *PROFILES[profile], "-oX", xml_path, "-n", "--open"]
    if ports:
        argv += ["-p", ports]
    argv.append(address)
    return argv


def _text(elem: ET.Element | None, attr: str) -> str | None:
    return elem.get(attr) if elem is not None else None


def parse_xml(xml_text: str) -> NmapResult:
    """Parse ``nmap -oX`` output into normalized observations."""
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - trusted tool output, no external entities
    except ET.ParseError as exc:
        raise NmapError(f"malformed nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapError(f"not an nmap XML document (root <{root.tag}>)")

    result = NmapResult()
    for host in root.findall("host"):
        addr = _host_address(host)
        if addr is None:
            continue
        status = host.find("status")
        state = _text(status, "state") or "unknown"
        hostnames = [
            hn.get("name", "") for hn in host.findall("hostnames/hostname") if hn.get("name")
        ]
        result.hosts.append(
            HostStatus(
                address=addr, state=state, reason=_text(status, "reason"), hostnames=hostnames
            )
        )
        for port in host.findall("ports/port"):
            _parse_port(addr, port, result)
    return result


def _host_address(host: ET.Element) -> str | None:
    # Prefer IPv4/IPv6 over MAC.
    for addr in host.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            return addr.get("addr")
    first = host.find("address")
    return first.get("addr") if first is not None else None


def _parse_port(addr: str, port: ET.Element, result: NmapResult) -> None:
    try:
        portnum = int(port.get("portid", ""))
    except ValueError:
        return
    protocol = port.get("protocol", "tcp")
    state_elem = port.find("state")
    state = _text(state_elem, "state") or "unknown"
    result.ports.append(
        PortState(
            address=addr,
            port=portnum,
            protocol=protocol,
            state=state,
            detail=_text(state_elem, "reason"),
        )
    )
    svc = port.find("service")
    if svc is not None and state == "open":
        cpes = [c.text for c in svc.findall("cpe") if c.text]
        result.services.append(
            Service(
                address=addr,
                port=portnum,
                protocol=protocol,
                service=svc.get("name", "unknown"),
                product=svc.get("product"),
                version=svc.get("version"),
                extrainfo=svc.get("extrainfo"),
                cpe=cpes,
                tunnel=svc.get("tunnel"),
                method=svc.get("method"),
            )
        )
