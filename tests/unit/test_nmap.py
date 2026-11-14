"""Nmap integration: argv construction and XML parsing."""

import pytest

from nxtsec.integrations.nmap import (
    DEFAULT_PROFILE,
    PROFILES,
    NmapError,
    build_argv,
    parse_xml,
)

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000005">
<status state="up" reason="syn-ack" reason_ttl="64"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="nas.home" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu" method="probed">
<cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.18.0" method="probed"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="conn-refused"/>
<service name="https" method="table"/></port>
</ports>
</host>
</nmaprun>"""

EMPTY_XML = """<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>"""
IPV6_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="2001:db8::1" addrtype="ipv6"/><ports></ports></host></nmaprun>"""


def test_build_argv_default():
    argv = build_argv("192.168.1.10", profile=DEFAULT_PROFILE, ports=None, xml_path="/tmp/x.xml")
    assert argv[0] == "nmap" and argv[-1] == "192.168.1.10"
    assert "-oX" in argv and "/tmp/x.xml" in argv and "--open" in argv and "-n" in argv
    assert "-sT" in argv  # connect scan, no raw sockets


def test_build_argv_ports():
    argv = build_argv("10.0.0.1", profile="service", ports="1-1024", xml_path="/tmp/x.xml")
    assert "-p" in argv and "1-1024" in argv and "-sV" in argv


def test_build_argv_unknown_profile():
    with pytest.raises(NmapError, match="unknown scan profile"):
        build_argv("10.0.0.1", profile="aggressive", ports=None, xml_path="/tmp/x.xml")


def test_all_profiles_connect_scan():
    # every shipped profile uses -sT (no raw sockets / privilege needed)
    for name, flags in PROFILES.items():
        assert "-sT" in flags, name


def test_parse_hosts_ports_services():
    r = parse_xml(SAMPLE_XML)
    assert len(r.hosts) == 1
    host = r.hosts[0]
    assert host.address == "192.168.1.10" and host.state == "up"  # ipv4 preferred over mac
    assert host.hostnames == ["nas.home"]

    ports = {p.port: p for p in r.ports}
    assert set(ports) == {22, 80, 443}
    assert ports[22].state == "open" and ports[443].state == "closed"

    # services only for open ports
    svcs = {s.port: s for s in r.services}
    assert set(svcs) == {22, 80}
    assert svcs[22].product == "OpenSSH" and svcs[22].version == "8.9p1"
    assert svcs[22].cpe == ["cpe:/a:openbsd:openssh:8.9p1"]
    assert svcs[80].service == "http" and svcs[80].product == "nginx"


def test_parse_observation_dicts_roundtrip():
    r = parse_xml(SAMPLE_XML)
    obs = [o.to_dict() for o in r.all_observations()]
    types = {o["type"] for o in obs}
    assert types == {"net.host", "net.port", "net.service"}


def test_parse_empty_and_ipv6():
    assert parse_xml(EMPTY_XML).hosts == []
    r = parse_xml(IPV6_XML)
    assert r.hosts[0].address == "2001:db8::1" and r.hosts[0].state == "up"


@pytest.mark.parametrize("bad", ["not xml at all", "<other>x</other>", "<nmaprun><host>"])
def test_parse_malformed(bad):
    with pytest.raises(NmapError):
        parse_xml(bad)
