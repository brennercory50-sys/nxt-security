"""network.nmap module: runs a fake nmap, parses output, enforces scope."""

import logging
import stat
import sys

import pytest

import nxtsec.modules.network.nmap_scan as mod
from nxtsec.core.errors import PluginError, ScopeViolation
from nxtsec.core.models import Mode, TargetType
from nxtsec.events import EventBus
from nxtsec.modules.network.nmap_scan import NmapScan, _validate_ports
from nxtsec.plugins import ModuleContext, Permission
from nxtsec.safety.scope import Scope
from nxtsec.targets import parse_target

SCOPE = Scope(["192.168.1.0/24", "scanme.test", "127.0.0.0/8"], attestation="authorized")

FAKE_XML = """<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/>
<address addr="{addr}" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" method="probed"/></port>
</ports></host></nmaprun>"""


def fake_nmap(tmp_path, *, xml=FAKE_XML, rc=0):
    """A stub executable that writes XML to the path after -oX and exits rc."""
    if sys.platform == "win32":
        pytest.skip("POSIX stub only")
    script = tmp_path / "nmap"
    script.write_text(
        "#!/bin/sh\n"
        "while [ $# -gt 0 ]; do\n"
        '  if [ "$1" = "-oX" ]; then shift; out="$1"; fi\n'
        '  last="$1"; shift\n'
        "done\n"
        f'cat > "$out" <<XML\n{xml.format(addr="192.168.1.10")}\nXML\n'
        f"exit {rc}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def ctx(options=None, nmap_path=None, scope=SCOPE, perms=None, evidence=None):
    captured = evidence if evidence is not None else []

    def sink(data, name, type_, desc):
        from nxtsec.core.models import Evidence

        captured.append((name, len(data)))
        return Evidence(
            type=type_,
            source="network.nmap",
            description=desc,
            content_sha256=Evidence.hash_bytes(data),
        )

    config = {"tools": {"nmap": {"path": nmap_path}}} if nmap_path else {}
    return ModuleContext(
        "asm_t",
        Mode.REAL,
        scope,
        frozenset(perms or {Permission.NETWORK_ACCESS, Permission.EXEC_TOOLS}),
        logging.getLogger("t"),
        EventBus(),
        options=options or {},
        module_name="network.nmap",
        config=config,
        evidence_sink=sink,
    )


@pytest.mark.parametrize("spec", ["22", "1-1024", "22,80,443", "1-100,443"])
def test_validate_ports_ok(spec):
    assert _validate_ports(spec) == spec


@pytest.mark.parametrize("spec", ["", "22; rm -rf /", "$(x)", "http", "a" * 300, "22|80"])
def test_validate_ports_bad(spec):
    with pytest.raises(PluginError):
        _validate_ports(spec)


def test_scan_ip_target(tmp_path):
    path = fake_nmap(tmp_path)
    ev = []
    res = NmapScan().run(parse_target("192.168.1.10"), ctx(nmap_path=path, evidence=ev))
    types = {o["type"] for o in res.observations}
    assert types == {"net.host", "net.port", "net.service"}
    assert res.commands and res.commands[0].startswith("nmap")
    assert ev and ev[0][0].endswith("nmap.xml")  # XML stored as evidence


def test_missing_nmap_is_error_not_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")  # nothing resolvable
    res = NmapScan().run(parse_target("192.168.1.10"), ctx())
    assert res.observations == [] and "nmap is not installed" in res.errors[0]


def test_hostname_resolution_scope_guard(tmp_path, monkeypatch):
    path = fake_nmap(tmp_path)
    monkeypatch.setattr(mod, "resolve_host", lambda h, timeout: ["10.9.9.9"])  # out of scope
    with pytest.raises(ScopeViolation):
        NmapScan().run(parse_target("scanme.test"), ctx(nmap_path=path))


def test_hostname_resolved_in_scope(tmp_path, monkeypatch):
    path = fake_nmap(tmp_path)
    monkeypatch.setattr(mod, "resolve_host", lambda h, timeout: ["192.168.1.10"])
    res = NmapScan().run(parse_target("scanme.test"), ctx(nmap_path=path))
    assert any(o["type"] == "net.service" for o in res.observations)


def test_unparseable_output_is_error(tmp_path):
    path = fake_nmap(tmp_path, xml="GARBAGE NOT XML")
    res = NmapScan().run(parse_target("192.168.1.10"), ctx(nmap_path=path))
    assert res.observations == [] and any("nmap" in e.lower() for e in res.errors)


def test_requires_exec_tools_permission(tmp_path):
    path = fake_nmap(tmp_path)
    with pytest.raises(PluginError, match="EXEC_TOOLS"):
        NmapScan().run(
            parse_target("192.168.1.10"), ctx(nmap_path=path, perms={Permission.NETWORK_ACCESS})
        )


def test_validate_options():
    NmapScan.validate_options({"network.nmap.profile": "service"})
    NmapScan.validate_options({"profile": "quick", "ports": "1-1024"})
    with pytest.raises(PluginError):
        NmapScan.validate_options({"profile": "nope"})
    with pytest.raises(PluginError):
        NmapScan.validate_options({"ports": "bad;rm"})


def test_manifest_requires_nmap_and_medium_risk():
    m = NmapScan.manifest
    assert "nmap" in m.requires_tools and m.risk_level.value == "medium"
    assert Permission.EXEC_TOOLS in m.permissions
    assert TargetType.IPV4 in m.target_types
