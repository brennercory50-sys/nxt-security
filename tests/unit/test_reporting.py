"""Reporting: Markdown/HTML/JSON/CSV rendering, determinism, redaction."""

import csv
import io
import json

import pytest

from nxtsec.reporting.report import ReportData, available_formats, render_report


def sample(findings=None, assessments=None):
    return ReportData.build(
        title="Test Report",
        operator="tester",
        scope_name="home-lab",
        findings=findings if findings is not None else _findings(),
        assessments=assessments
        or [
            {
                "id": "asm_1",
                "target": {"raw": "example.com"},
                "mode": "real",
                "status": "completed",
                "created_at": "2026-10-10T00:00:00+00:00",
                "modules": ["dns.records", "tls.certificate"],
            }
        ],
        evidence_count=3,
    )


def _findings():
    return [
        {
            "id": "fnd_a",
            "severity": "HIGH",
            "status": "OPEN",
            "confidence": "FIRM",
            "title": "Expired certificate",
            "target": "example.com:443",
            "detection_module": "tls.certificate",
            "cwe": "CWE-298",
            "description": "d",
            "impact": "i",
            "remediation": "renew",
            "references": ["https://example.test/rfc"],
            "evidence_ids": ["evd_1"],
            "created_at": "2026-10-10T00:00:00+00:00",
        },
        {
            "id": "fnd_b",
            "severity": "LOW",
            "status": "CONFIRMED",
            "confidence": "FIRM",
            "title": "No DMARC record",
            "target": "example.com",
            "detection_module": "dns.records",
            "created_at": "2026-10-10T01:00:00+00:00",
        },
    ]


def test_formats_available():
    assert set(available_formats()) == {"markdown", "html", "json", "csv"}


def test_markdown_structure_and_order():
    md = render_report(sample(), "markdown")
    for heading in (
        "# Test Report",
        "## Executive summary",
        "## Severity distribution",
        "## Methodology",
        "## Scope",
        "## Findings",
        "## Appendix",
    ):
        assert heading in md
    # severe first
    assert md.index("Expired certificate") < md.index("No DMARC record")
    assert "2 finding(s): 1 high, 1 low" in md
    assert "renew" in md and "CWE-298" in md


def test_json_shape():
    data = json.loads(render_report(sample(), "json"))
    assert data["severity_distribution"]["HIGH"] == 1
    assert data["findings"][0]["severity"] == "HIGH"
    assert data["evidence_count"] == 3 and data["modules"] == ["dns.records", "tls.certificate"]


def test_csv_rows():
    text = render_report(sample(), "csv")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 2 and rows[0]["severity"] == "HIGH"
    assert rows[0]["title"] == "Expired certificate"


def test_html_self_contained():
    out = render_report(sample(), "html")
    assert out.startswith("<!doctype html>") and "</html>" in out
    assert "<style>" in out and "http" not in out.split("<style>")[0]  # no external links in head
    assert "Expired certificate" in out and "Severity distribution" in out


def test_empty_report():
    md = render_report(sample(findings=[]), "markdown")
    assert "No findings were recorded." in md
    assert "0 finding(s)" in md


def test_redaction_in_all_formats():
    secret = "AKIAIOSFODNN7EXAMPLE"
    findings = [
        {
            "id": "fnd_x",
            "severity": "HIGH",
            "status": "OPEN",
            "confidence": "FIRM",
            "title": f"Leaked key {secret}",
            "target": "h",
            "detection_module": "m",
            "description": f"found {secret}",
            "created_at": "2026-10-10T00:00:00+00:00",
        }
    ]
    for fmt in available_formats():
        assert secret not in render_report(sample(findings=findings), fmt), fmt


def test_deterministic():
    a = render_report(sample(), "markdown")
    b = render_report(sample(), "markdown")
    assert a == b


def test_unknown_format():
    with pytest.raises(ValueError, match="unknown report format"):
        render_report(sample(), "pdf")


def test_html_escapes_markup():
    findings = [
        {
            "id": "fnd_x",
            "severity": "LOW",
            "status": "OPEN",
            "confidence": "FIRM",
            "title": "<script>alert(1)</script>",
            "target": "h",
            "detection_module": "m",
            "created_at": "2026-10-10T00:00:00+00:00",
        }
    ]
    out = render_report(sample(findings=findings), "html")
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
