"""Built-in seed modules: network.tcp_connect, dns.resolve, forensics.hash."""

import hashlib
import logging
import os
import socket
import sys

import pytest

from nxtsec.core.errors import PluginError, ScopeViolation
from nxtsec.core.models import Mode
from nxtsec.events import EventBus
from nxtsec.modules.builtin import BUILTIN_PLUGINS, register_builtins
from nxtsec.modules.dns import resolve as dns_mod
from nxtsec.modules.dns.resolve import DnsResolve
from nxtsec.modules.forensics.hashes import FileHash
from nxtsec.modules.network import tcp_connect as tcp_mod
from nxtsec.modules.network.tcp_connect import TcpConnect, parse_ports
from nxtsec.plugins import ModuleContext, Permission, PluginRegistry
from nxtsec.safety.scope import Scope
from nxtsec.targets import parse_target

SCOPE = Scope(
    ["localhost", "127.0.0.0/8", "app.example.test", "nas.home.test"],
    ["127.0.0.2"],
    attestation="test",
)


def ctx(options=None, module="", perms=(Permission.NETWORK_ACCESS,), scope=SCOPE):
    return ModuleContext(
        "asm_t",
        Mode.REAL,
        scope,
        frozenset(perms),
        logging.getLogger("t"),
        EventBus(),
        options=options or {},
        module_name=module,
    )


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    yield s.getsockname()[1]
    s.close()


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_builtins_register_and_validate():
    reg = PluginRegistry()
    register_builtins(reg)
    assert len(reg) == len(BUILTIN_PLUGINS) >= 3


# -- tcp_connect -----------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("22", [22]),
        ("80, 22,80", [22, 80]),
        ("8000-8003", [8000, 8001, 8002, 8003]),
        ("1-1024", list(range(1, 1025))),
    ],
)
def test_parse_ports(raw, expected):
    assert parse_ports(raw) == expected


@pytest.mark.parametrize(
    "raw", ["", "abc", "0", "65536", "10-5", "1-2000", "22,,x", "-5", "1-70000"]
)
def test_parse_ports_invalid(raw):
    with pytest.raises(PluginError):
        parse_ports(raw)


def test_validate_options():
    TcpConnect.validate_options({"ports": "22"})
    TcpConnect.validate_options({"network.tcp_connect.timeout": "1.5"})
    with pytest.raises(PluginError):
        TcpConnect.validate_options({"ports": "nope"})
    with pytest.raises(PluginError):
        TcpConnect.validate_options({"timeout": "999"})


def test_open_and_closed(listener):
    closed = closed_port()
    # generous timeout: Windows takes ~1-2 s to report a refused connection
    opts = {"ports": f"{listener},{closed}", "timeout": "10"}
    res = TcpConnect().run(parse_target("127.0.0.1"), ctx(opts, "network.tcp_connect"))
    states = {o["port"]: o["state"] for o in res.observations}
    assert states == {listener: "open", closed: "closed"}


def test_namespaced_option_wins(listener):
    c = ctx({"ports": "1", "network.tcp_connect.ports": str(listener)}, "network.tcp_connect")
    res = TcpConnect().run(parse_target("127.0.0.1"), c)
    assert [o["port"] for o in res.observations] == [listener]


def test_url_target_uses_url_port(listener):
    res = TcpConnect().run(parse_target(f"http://127.0.0.1:{listener}/x"), ctx())
    assert [(o["port"], o["state"]) for o in res.observations] == [(listener, "open")]


def test_hostname_resolution_guard(monkeypatch):
    # in-scope name pointing at a denied address
    monkeypatch.setattr(tcp_mod, "resolve_host", lambda h, timeout: ["127.0.0.2"])
    with pytest.raises(ScopeViolation, match="denied"):
        TcpConnect().run(parse_target("app.example.test"), ctx({"ports": "80"}))
    # in-scope name pointing into an internal network that is not in scope
    monkeypatch.setattr(tcp_mod, "resolve_host", lambda h, timeout: ["10.9.9.9"])
    with pytest.raises(ScopeViolation, match="internal address"):
        TcpConnect().run(parse_target("nas.home.test"), ctx({"ports": "80"}))


def test_hostname_unresolvable(monkeypatch):
    def fail(h, timeout):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(tcp_mod, "resolve_host", fail)
    with pytest.raises(PluginError, match="cannot resolve"):
        TcpConnect().run(parse_target("app.example.test"), ctx({"ports": "80"}))


def test_localhost_name(listener):
    res = TcpConnect().run(parse_target("localhost"), ctx({"ports": str(listener)}))
    assert any(o["state"] == "open" for o in res.observations)


def test_requires_permission():
    with pytest.raises(PluginError, match="NETWORK_ACCESS"):
        TcpConnect().run(parse_target("127.0.0.1"), ctx(perms=()))


def test_cancel_before_probing():
    c = ctx({"ports": "80"})
    c.cancel_check = lambda: True
    from nxtsec.core.errors import Cancelled

    with pytest.raises(Cancelled):
        TcpConnect().run(parse_target("127.0.0.1"), c)


# -- dns.resolve ---------------------------------------------------------------------
def test_dns_localhost():
    res = DnsResolve().run(parse_target("localhost"), ctx())
    addrs = {o["address"] for o in res.observations if o["type"] == "dns.address"}
    assert addrs & {"127.0.0.1", "::1"}


def test_dns_records_and_scope_notice(monkeypatch):
    monkeypatch.setattr(dns_mod, "resolve_host", lambda h, t: ["93.184.216.34", "10.1.1.1"])
    res = DnsResolve().run(parse_target("app.example.test"), ctx())
    recs = [(o["record"], o["address"]) for o in res.observations if o["type"] == "dns.address"]
    assert recs == [("A", "93.184.216.34"), ("A", "10.1.1.1")]
    notices = [o for o in res.observations if o["type"] == "scope.notice"]
    assert notices and "10.1.1.1" in notices[0]["detail"]


def test_dns_nxdomain_is_a_result_not_a_crash(monkeypatch):
    def fail(h, t):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(dns_mod, "resolve_host", fail)
    res = DnsResolve().run(parse_target("app.example.test"), ctx())
    assert res.observations == [] and "did not resolve" in res.errors[0]


def test_dns_reverse_loopback():
    res = DnsResolve().run(parse_target("127.0.0.1"), ctx())
    assert res.observations or res.errors  # PTR may legitimately be absent


# -- forensics.hash ------------------------------------------------------------------
FILE_CTX = dict(perms=(Permission.LOCAL_FILES, Permission.READ_ONLY))


def test_hash_known_vector(tmp_path):
    p = tmp_path / "abc.txt"
    p.write_bytes(b"abc")
    [o] = FileHash().run(parse_target(f"file:{p}"), ctx(**FILE_CTX)).observations
    assert o["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert o["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert o["sha512"] == hashlib.sha512(b"abc").hexdigest() and o["size"] == 3


def test_hash_directory_tree_and_limit(tmp_path):
    for i in range(5):
        (tmp_path / f"d{i % 2}").mkdir(exist_ok=True)
        (tmp_path / f"d{i % 2}" / f"f{i}.bin").write_bytes(bytes([i]) * 100)
    res = FileHash().run(parse_target(f"file:{tmp_path}"), ctx(**FILE_CTX))
    assert len([o for o in res.observations if o["type"] == "file.hash"]) == 5
    res = FileHash().run(parse_target(f"file:{tmp_path}"), ctx({"max_files": "2"}, **FILE_CTX))
    assert len(res.observations) == 2 and "max_files=2" in res.errors[0]


def test_hash_does_not_modify_file(tmp_path):
    p = tmp_path / "evidence.bin"
    p.write_bytes(b"x" * 10000)
    before = os.stat(p)
    FileHash().run(parse_target(f"file:{p}"), ctx(**FILE_CTX))
    after = os.stat(p)
    assert (before.st_mtime_ns, before.st_size) == (after.st_mtime_ns, after.st_size)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_symlinks_not_followed(tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("x")
    d = tmp_path / "case"
    d.mkdir()
    try:
        (d / "link").symlink_to(secret)
    except OSError:
        pytest.skip("symlink not permitted")
    res = FileHash().run(parse_target(f"file:{d}"), ctx(**FILE_CTX))
    assert [o["type"] for o in res.observations] == ["file.symlink"]


@pytest.mark.skipif(sys.platform == "win32" or not hasattr(os, "mkfifo"), reason="POSIX FIFO")
def test_fifo_skipped_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    res = FileHash().run(parse_target(f"file:{tmp_path}"), ctx(**FILE_CTX))
    assert res.observations[0]["type"] == "file.skipped"
    with pytest.raises(PluginError, match="not a regular file"):
        FileHash().run(parse_target(f"file:{tmp_path / 'pipe'}"), ctx(**FILE_CTX))


def test_hash_missing(tmp_path):
    with pytest.raises(PluginError, match="no such file"):
        FileHash().run(parse_target(f"file:{tmp_path / 'nope'}"), ctx(**FILE_CTX))


def test_hash_requires_local_files_permission(tmp_path):
    with pytest.raises(PluginError):
        FileHash().run(parse_target(f"file:{tmp_path}"), ctx(perms=(Permission.READ_ONLY,)))
