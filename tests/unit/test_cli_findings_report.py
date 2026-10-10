"""CLI: findings triage and report generation, end to end."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nxtsec.cli.main import cli
from nxtsec.core.app import App
from nxtsec.core.models import Confidence, Finding, Severity

EXAMPLE_SCOPE = Path(__file__).resolve().parents[2] / "config" / "scope.example.yaml"


@pytest.fixture(autouse=True)
def _scope(monkeypatch):
    monkeypatch.setenv("NXTSEC_PATHS__SCOPE_FILE", str(EXAMPLE_SCOPE))


def run(*args):
    return CliRunner().invoke(cli, ["--no-log-file", *args], obj={})


def seed():
    """Insert findings directly via a fresh App (same NXTSEC_HOME as the CLI)."""
    app = App.create(log_to_file=False)
    ids = {}
    for title, sev, module in [
        ("Expired certificate", Severity.HIGH, "tls.certificate"),
        ("No DMARC record", Severity.LOW, "dns.records"),
        ("Weak key", Severity.MEDIUM, "tls.certificate"),
    ]:
        f = Finding(title, sev, "example.com", module, confidence=Confidence.FIRM)
        fid, _ = app.db.upsert_finding(f)
        ids[title] = fid
    app.db.close()
    return ids


def test_findings_list_and_filter():
    seed()
    rows = json.loads(run("findings", "list", "--json").output)
    assert [r["severity"] for r in rows][:2] == ["HIGH", "MEDIUM"]  # sorted severe-first
    high = json.loads(run("findings", "list", "--min-severity", "MEDIUM", "--json").output)
    assert all(r["severity"] in ("HIGH", "MEDIUM") for r in high) and len(high) == 2
    mod = json.loads(run("findings", "list", "--module", "dns.records", "--json").output)
    assert len(mod) == 1 and mod[0]["title"] == "No DMARC record"


def test_findings_triage_flow():
    ids = seed()
    fid = ids["Expired certificate"]
    assert run("findings", "set-status", fid, "confirmed", "--note", "reproduced").exit_code == 0
    shown = json.loads(run("findings", "show", fid, "--json").output)
    assert shown["status"] == "CONFIRMED" and shown["notes"][0]["text"] == "reproduced"
    # invalid transition rejected
    bad = run("findings", "set-status", fid, "open")
    assert bad.exit_code != 0
    # note + stats
    assert run("findings", "note", fid[:12], "owner notified").exit_code == 0
    stats = json.loads(run("findings", "stats", "--json").output)
    assert stats["total"] == 3 and stats["by_status"]["CONFIRMED"] == 1


def test_findings_show_unknown():
    seed()
    assert run("findings", "show", "fnd_nope").exit_code != 0


def test_report_markdown_stdout():
    seed()
    r = run("report", "--format", "markdown")
    assert r.exit_code == 0
    assert "# NXT-Security findings report" in r.output
    assert "Expired certificate" in r.output and "## Severity distribution" in r.output


def test_report_to_file_all_formats(tmp_path):
    seed()
    for fmt, ext in [("markdown", "md"), ("html", "html"), ("json", "json"), ("csv", "csv")]:
        out = tmp_path / f"r.{ext}"
        r = run("report", "--format", fmt, "-o", str(out))
        assert r.exit_code == 0 and out.is_file()
        assert "finding(s)" in r.output
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["severity_distribution"]["HIGH"] == 1


def test_report_min_severity_and_open_filters():
    seed()
    data = json.loads(run("report", "--format", "json", "--min-severity", "HIGH").output)
    assert {f["severity"] for f in data["findings"]} == {"HIGH"}


def test_report_unknown_assessment():
    seed()
    assert run("report", "--assessment", "asm_nope").exit_code != 0
