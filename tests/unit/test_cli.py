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
    for cmd in ([], ["config"], ["scope"], ["plugins"], ["scope", "check"]):
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
