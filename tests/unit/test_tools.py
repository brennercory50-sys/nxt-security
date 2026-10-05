import os
import stat
import sys
from pathlib import Path

import pytest

from nxtsec.integrations.tools import ToolRegistry, ToolSpec, ToolStatus, parse_version, version_lt


def _script(tmp_path: Path, name: str, body: str) -> Path:
    """Create an executable fake tool that prints ``body``."""
    if sys.platform == "win32":
        pytest.skip("shell-script fakes are POSIX-only")
    p = tmp_path / name
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def _spec(**kw):
    base = dict(
        name="faketool",
        description="d",
        category="test",
        binary="faketool",
        version_args=("--version",),
        version_regex=r"faketool (\d+\.\d+\.\d+)",
        documentation="",
        install={"linux": "apt install faketool"},
    )
    base.update(kw)
    return ToolSpec(**base)


def _reg(spec, path, system="linux"):
    return ToolRegistry((spec,), overrides={spec.name: {"path": str(path)}}, system=system)


def test_installed(tmp_path):
    p = _script(tmp_path, "faketool", "echo 'faketool 2.1.0'")
    st = _reg(_spec(), p).check("faketool")
    assert st.status == ToolStatus.INSTALLED and st.version == "2.1.0"


def test_outdated(tmp_path):
    p = _script(tmp_path, "faketool", "echo 'faketool 1.0.0'")
    st = _reg(_spec(min_version="2.0"), p).check("faketool")
    assert st.status == ToolStatus.OUTDATED


def test_broken_exit_code(tmp_path):
    p = _script(tmp_path, "faketool", "echo boom >&2; exit 2")
    assert _reg(_spec(), p).check("faketool").status == ToolStatus.BROKEN


def test_missing_from_path(monkeypatch):
    monkeypatch.setenv("PATH", "")
    reg = ToolRegistry((_spec(),), system="linux")
    st = reg.check("faketool")
    assert st.status == ToolStatus.MISSING and "apt install" in st.detail


def test_configured_path_missing(tmp_path):
    st = _reg(_spec(), tmp_path / "nope").check("faketool")
    assert st.status == ToolStatus.MISSING and "configured path" in st.detail


def test_unsupported_platform():
    reg = ToolRegistry((_spec(platforms=frozenset({"linux"})),), system="termux")
    assert reg.check("faketool").status == ToolStatus.UNSUPPORTED


def test_unknown_tool():
    with pytest.raises(KeyError):
        ToolRegistry().get("nope")


def test_builtin_registry_metadata():
    names = {s.name for s in ToolRegistry().specs()}
    assert {"nmap", "tshark", "dig", "whois", "curl", "openssl", "python", "git", "yara"} <= names
    for s in ToolRegistry().specs():
        d = s.to_dict()
        assert d["install_method"] and d["version_command"][0] == s.binary


def test_real_python_detected():
    reg = ToolRegistry(
        overrides={"python": {"path": sys.executable}},
        system="windows" if os.name == "nt" else "linux",
    )
    st = reg.check("python")
    assert st.status == ToolStatus.INSTALLED
    assert st.version and st.version.startswith(f"{sys.version_info.major}.")


@pytest.mark.parametrize(
    ("a", "b", "lt"),
    [
        ("7.80", "7.9", False),
        ("7.8", "7.80", True),
        ("3.10.1", "3.10", False),
        ("1.0", "1.0.1", True),
        ("x", "1.0", False),
    ],
)
def test_version_lt(a, b, lt):
    assert version_lt(a, b) is lt


def test_parse_version():
    assert parse_version("3.11.4") == (3, 11, 4) and parse_version("abc") is None
