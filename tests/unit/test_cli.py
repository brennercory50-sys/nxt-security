import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nxtsec import __version__
from nxtsec.cli.main import cli

EXAMPLE_SCOPE = Path(__file__).resolve().parents[2] / "config" / "scope.example.yaml"


@pytest.fixture(autouse=True)
def _scope(monkeypatch):
    monkeypatch.setenv("NXTSEC_PATHS__SCOPE_FILE", str(EXAMPLE_SCOPE))


def run(*args):
    return CliRunner().invoke(cli, ["--no-log-file", *args], obj={})


def test_help_everywhere():
    from nxtsec.cli.main import cli as root

    groups = [[]] + [[n] for n in root.commands]
    groups += [[n, sub] for n, c in root.commands.items() for sub in getattr(c, "commands", {})]
    for cmd in groups:
        r = run(*cmd, "--help")
        assert r.exit_code == 0, r.output
        assert "Usage" in r.output


def test_version():
    r = run("version", "--json")
    assert r.exit_code == 0 and json.loads(r.output)["nxtsec"] == __version__
    assert __version__ in run("--version").output


def test_config_show_and_validate():
    r = run("config", "show", "--json")
    assert r.exit_code == 0
    assert "settings" in json.loads(r.output)
    r = run("config", "validate")
    assert r.exit_code == 0 and "[OK] configuration" in r.output


def test_scope_check_exit_codes():
    ok = run("scope", "check", "127.0.0.1", "192.168.1.20")
    assert ok.exit_code == 0 and "[IN SCOPE]" in ok.output
    bad = run("scope", "check", "8.8.8.8", "--json")
    assert bad.exit_code == 3
    assert json.loads(bad.output)[0]["allowed"] is False


def test_plugins_list():
    r = run("plugins", "list", "--json")
    assert r.exit_code == 0 and "plugins" in json.loads(r.output)


def test_bad_config_path(tmp_path):
    r = CliRunner().invoke(cli, ["--config", str(tmp_path / "x.yaml"), "config", "show"], obj={})
    assert r.exit_code != 0 and "not found" in r.output


def test_doctor_json():
    r = run("doctor", "--json")
    assert r.exit_code in (0, 1), r.output
    data = json.loads(r.output)
    assert data["overall"] in ("READY", "DEGRADED", "NOT READY")
    names = {c["name"] for c in data["checks"]}
    assert {"Platform", "Python", "Database", "Scope", "git"} <= names


def test_doctor_human():
    r = run("doctor")
    assert "NXT-SECURITY SYSTEM CHECK" in r.output and "Overall:" in r.output


def test_tools_commands():
    r = run("tools", "list", "--json")
    assert {t["name"] for t in json.loads(r.output)} >= {"nmap", "git"}
    r = run("tools", "check", "git", "--json")
    assert json.loads(r.output)[0]["status"] in ("INSTALLED", "OUTDATED", "BROKEN", "MISSING")
    assert run("tools", "check", "nonexistent").exit_code != 0
    assert run("tools", "info", "nmap").exit_code == 0
    assert run("tools").exit_code in (0, 1)


def test_target_lifecycle():
    r = run("target", "add", "192.168.1.20", "--label", "nas")
    assert r.exit_code == 0 and "Added" in r.output
    assert "Already saved" in run("target", "add", "192.168.1.20").output
    out = run("target", "add", "8.8.8.8")
    assert out.exit_code != 0 and "out of scope" in out.output
    assert run("target", "add", "not a target").exit_code != 0
    rows = json.loads(run("target", "list", "--json").output)
    assert [r["value"] for r in rows] == ["192.168.1.20"] and rows[0]["in_scope"]
    assert run("target", "remove", "192.168.1.20").exit_code == 0
    assert run("target", "remove", "192.168.1.20").exit_code != 0


def test_target_parse():
    d = json.loads(run("target", "parse", "https://localhost:8443/x").output)
    assert d["type"] == "url" and d["host"] == "localhost" and d["in_scope"]


def test_config_path_and_init_scope(tmp_path, monkeypatch):
    dest = tmp_path / "scope.yaml"
    monkeypatch.setenv("NXTSEC_PATHS__SCOPE_FILE", str(dest))
    assert run("config", "init-scope").exit_code == 0 and dest.is_file()
    assert run("config", "init-scope").exit_code != 0
    assert run("config", "init-scope", "--force").exit_code == 0
    assert "scope" in run("config", "path").output


def test_logs_command():
    r = CliRunner().invoke(cli, ["target", "parse", "localhost"], obj={})
    assert r.exit_code == 0
    r = run("logs", "-n", "5")
    assert r.exit_code == 0
