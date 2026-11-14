"""CLI: nxtsec ai status / analyze / summarize (offline provider, no network)."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nxtsec.cli.main import cli
from nxtsec.core.app import App
from nxtsec.core.models import Confidence, Finding, Severity

EXAMPLE_SCOPE = Path(__file__).resolve().parents[2] / "config" / "scope.example.yaml"
SECRET = "gh" + "p_" + "Q9w8E7r6T5y4U3i2O1p0A9s8D7f6G5h4J3k2"


@pytest.fixture(autouse=True)
def _scope(monkeypatch):
    monkeypatch.setenv("NXTSEC_PATHS__SCOPE_FILE", str(EXAMPLE_SCOPE))


def run(*args):
    return CliRunner().invoke(cli, ["--no-log-file", *args], obj={})


def seed_finding():
    app = App.create(log_to_file=False)
    f = Finding(
        "Hardcoded token in app.py:3",
        Severity.CRITICAL,
        "/repo/app.py",
        "secrets.scan",
        confidence=Confidence.FIRM,
        component=f"github_token {SECRET}",
        description=f"secret: {SECRET}",
    )
    fid, _ = app.db.upsert_finding(f)
    app.db.close()
    return fid


def test_ai_status_offline_default():
    r = run("ai", "status", "--json")
    assert r.exit_code == 0
    info = json.loads(r.output)
    assert info["provider"] == "offline" and info["ready"] is True


def test_ai_status_claude_not_ready(monkeypatch):
    monkeypatch.setenv("NXTSEC_AI__PROVIDER", "claude")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    info = json.loads(run("ai", "status", "--json").output)
    assert info["provider"] == "claude" and info["ready"] is False


def test_ai_analyze_offline_and_redacts():
    fid = seed_finding()
    r = run("ai", "analyze", fid)
    assert r.exit_code == 0
    assert "advisory" in r.output.lower()
    assert SECRET not in r.output  # raw secret never printed


def test_ai_analyze_annotate_persists_note():
    fid = seed_finding()
    assert run("ai", "analyze", fid, "--annotate").exit_code == 0
    shown = json.loads(run("findings", "show", fid, "--json").output)
    assert shown["notes"] and "advisory" in shown["notes"][-1]["text"].lower()
    assert shown["severity"] == "CRITICAL"  # unchanged by AI


def test_ai_summarize():
    seed_finding()
    r = run("ai", "summarize")
    assert r.exit_code == 0 and "advisory" in r.output.lower()


def test_ai_summarize_empty():
    r = run("ai", "summarize")
    assert r.exit_code == 0 and "No findings" in r.output


def test_ai_analyze_unknown_finding():
    seed_finding()
    assert run("ai", "analyze", "fnd_nope").exit_code != 0
