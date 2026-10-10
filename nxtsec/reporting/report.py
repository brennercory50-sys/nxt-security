"""Render assessment/finding data into shareable reports.

A report is built from a :class:`ReportData` snapshot (assembled by the CLI
from the database) and rendered to Markdown, JSON, CSV or a self-contained
HTML file. All rendered text is redacted. Reports are deterministic given the
same data, so they diff cleanly.

Sections: executive summary, scope, methodology, severity distribution,
findings (with evidence references and remediation), and an appendix.
"""

from __future__ import annotations

import csv
import html
import io
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from nxtsec.core.models import Severity
from nxtsec.safety.redaction import redact, redact_obj

AVAILABLE_FORMATS = ("markdown", "html", "json", "csv")
SEVERITY_ORDER = [s.value for s in reversed(list(Severity))]  # CRITICAL..INFO


def available_formats() -> tuple[str, ...]:
    return AVAILABLE_FORMATS


@dataclass
class ReportData:
    title: str
    generated_at: str
    operator: str
    scope_name: str
    findings: list[dict[str, Any]]
    assessments: list[dict[str, Any]] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    evidence_count: int = 0

    @classmethod
    def build(
        cls,
        *,
        title: str,
        operator: str,
        scope_name: str,
        findings: Sequence[dict[str, Any]],
        assessments: Sequence[dict[str, Any]] = (),
        evidence_count: int = 0,
    ) -> ReportData:
        modules = sorted({m for a in assessments for m in a.get("modules", [])})
        return cls(
            title=title,
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            operator=operator,
            scope_name=scope_name,
            findings=list(findings),
            assessments=list(assessments),
            modules=modules,
            evidence_count=evidence_count,
        )

    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            if f["severity"] in counts:
                counts[f["severity"]] += 1
        return counts

    def sorted_findings(self) -> list[dict[str, Any]]:
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return sorted(
            self.findings,
            key=lambda f: (order.get(f["severity"], 99), f.get("created_at") or ""),
        )


def render_report(data: ReportData, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "markdown":
        return _markdown(data)
    if fmt == "html":
        return _html(data)
    if fmt == "json":
        return _json(data)
    if fmt == "csv":
        return _csv(data)
    raise ValueError(f"unknown report format {fmt!r}; choose from {AVAILABLE_FORMATS}")


def _summary_line(counts: dict[str, int]) -> str:
    total = sum(counts.values())
    parts = [f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER if counts[s]]
    return f"{total} finding(s)" + (": " + ", ".join(parts) if parts else "")


def _json(data: ReportData) -> str:
    payload = {
        "title": data.title,
        "generated_at": data.generated_at,
        "operator": data.operator,
        "scope": data.scope_name,
        "modules": data.modules,
        "evidence_count": data.evidence_count,
        "severity_distribution": data.severity_counts(),
        "assessments": [
            {k: a.get(k) for k in ("id", "target", "status", "mode", "created_at")}
            for a in data.assessments
        ],
        "findings": data.sorted_findings(),
    }
    return json.dumps(redact_obj(payload), indent=2, default=str)


def _csv(data: ReportData) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id",
            "severity",
            "status",
            "confidence",
            "title",
            "target",
            "component",
            "module",
            "cwe",
            "created_at",
        ]
    )
    for f in data.sorted_findings():
        writer.writerow(
            [
                f.get("id", ""),
                f.get("severity", ""),
                f.get("status", ""),
                f.get("confidence", ""),
                redact(f.get("title", "")),
                redact(f.get("target", "")),
                redact(f.get("component") or ""),
                f.get("detection_module", ""),
                f.get("cwe") or "",
                f.get("created_at", ""),
            ]
        )
    return buf.getvalue()


def _markdown(data: ReportData) -> str:
    counts = data.severity_counts()
    out: list[str] = [f"# {redact(data.title)}", ""]
    out += [
        f"- **Generated:** {data.generated_at}",
        f"- **Operator:** {redact(data.operator)}",
        f"- **Scope:** {redact(data.scope_name)}",
        f"- **Assessments:** {len(data.assessments)}",
        f"- **Evidence items:** {data.evidence_count}",
        "",
        "## Executive summary",
        "",
        _summary_line(counts) + ".",
        "",
        "## Severity distribution",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    out += [f"| {s} | {counts[s]} |" for s in SEVERITY_ORDER]
    out += ["", "## Methodology", ""]
    out.append(
        "Findings were produced by the following NXT-Security modules, each run only against "
        "in-scope, authorized targets: "
        + (", ".join(f"`{m}`" for m in data.modules) or "n/a")
        + "."
    )
    out += ["", "## Scope", "", f"Assessment scope: **{redact(data.scope_name)}**.", ""]
    if data.assessments:
        out += [
            "| Assessment | Target | Mode | Status | Created |",
            "| --- | --- | --- | --- | --- |",
        ]
        for a in data.assessments:
            t = a.get("target", {})
            target = t.get("raw") if isinstance(t, dict) else t
            out.append(
                f"| {a.get('id', '')} | {redact(str(target))} | {a.get('mode', '')} "
                f"| {a.get('status', '')} | {a.get('created_at', '')} |"
            )
        out.append("")
    out += ["## Findings", ""]
    findings = data.sorted_findings()
    if not findings:
        out += ["No findings were recorded.", ""]
    for i, f in enumerate(findings, 1):
        out += [
            f"### {i}. [{f['severity']}] {redact(f['title'])}",
            "",
            f"- **Status:** {f.get('status', 'OPEN')}  |  **Confidence:** "
            f"{f.get('confidence', '')}  |  **Module:** {f.get('detection_module', '')}",
            f"- **Target:** {redact(f.get('target', ''))}"
            + (f"  |  **Component:** {redact(f['component'])}" if f.get("component") else ""),
        ]
        if f.get("cwe") or f.get("cvss") is not None:
            out.append(f"- **CWE:** {f.get('cwe') or 'n/a'}  |  **CVSS:** {f.get('cvss') or 'n/a'}")
        for label, key in (
            ("Description", "description"),
            ("Impact", "impact"),
            ("Remediation", "remediation"),
        ):
            if f.get(key):
                out += ["", f"**{label}.** {redact(f[key])}"]
        if f.get("references"):
            out += ["", "**References:**"] + [f"- {redact(r)}" for r in f["references"]]
        if f.get("evidence_ids"):
            out += ["", f"**Evidence:** {', '.join(f['evidence_ids'])}"]
        if f.get("notes"):
            out += ["", "**Notes:**"]
            out += [f"- {n['at']} ({redact(n['by'])}): {redact(n['text'])}" for n in f["notes"]]
        out.append("")
    out += [
        "## Appendix",
        "",
        "This report was generated by NXT-Security for authorized security assessment. "
        "Findings describe the configuration of systems the operator attested authorization "
        "to test. Secrets are redacted throughout.",
        "",
    ]
    return "\n".join(out)


_SEV_COLOR = {
    "CRITICAL": "#7c2d12",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#1d4ed8",
    "INFO": "#334155",
}


def _html(data: ReportData) -> str:
    counts = data.severity_counts()

    def esc(value: Any) -> str:
        return html.escape(redact(str(value)))

    rows = "".join(
        f'<tr><td><span class="sev" style="background:{_SEV_COLOR[s]}">{s}</span></td>'
        f"<td>{counts[s]}</td></tr>"
        for s in SEVERITY_ORDER
    )
    cards: list[str] = []
    for i, f in enumerate(data.sorted_findings(), 1):
        sev = f["severity"]
        detail = []
        for label, key in (
            ("Description", "description"),
            ("Impact", "impact"),
            ("Remediation", "remediation"),
        ):
            if f.get(key):
                detail.append(f"<p><strong>{label}.</strong> {esc(f[key])}</p>")
        refs = ""
        if f.get("references"):
            items = "".join(f"<li>{esc(r)}</li>" for r in f["references"])
            refs = f"<p><strong>References</strong></p><ul>{items}</ul>"
        meta = (
            f"Status {esc(f.get('status', 'OPEN'))} · Confidence {esc(f.get('confidence', ''))} "
            f"· Module {esc(f.get('detection_module', ''))}"
            + (f" · {esc(f.get('cwe'))}" if f.get("cwe") else "")
        )
        cards.append(
            f'<section class="finding"><h3>'
            f'<span class="sev" style="background:{_SEV_COLOR.get(sev, "#334155")}">{sev}</span> '
            f"{i}. {esc(f['title'])}</h3>"
            f'<p class="meta">{meta}</p>'
            f"<p><strong>Target.</strong> {esc(f.get('target', ''))}"
            + (f" — {esc(f['component'])}" if f.get("component") else "")
            + "</p>"
            + "".join(detail)
            + refs
            + "</section>"
        )
    findings_html = "".join(cards) or "<p>No findings were recorded.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(data.title)}</title>
<style>
:root {{ color-scheme: light dark; --fg:#0f172a; --bg:#ffffff; --muted:#64748b;
  --card:#f8fafc; --border:#e2e8f0; }}
@media (prefers-color-scheme: dark) {{ :root {{ --fg:#e2e8f0; --bg:#0f172a;
  --muted:#94a3b8; --card:#1e293b; --border:#334155; }} }}
* {{ box-sizing:border-box; }}
body {{ font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; color:var(--fg);
  background:var(--bg); margin:0; padding:2rem 1rem; }}
main {{ max-width:900px; margin:0 auto; }}
h1 {{ font-size:1.8rem; margin:0 0 .25rem; }}
h2 {{ margin-top:2.5rem; border-bottom:1px solid var(--border); padding-bottom:.3rem; }}
.meta-list {{ color:var(--muted); font-size:.95rem; }}
table {{ border-collapse:collapse; width:100%; margin:1rem 0; }}
td,th {{ text-align:left; padding:.4rem .6rem; border-bottom:1px solid var(--border); }}
.sev {{ color:#fff; padding:.08rem .5rem; border-radius:999px; font-size:.78rem;
  font-weight:600; letter-spacing:.02em; }}
.finding {{ background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:1rem 1.25rem; margin:1rem 0; }}
.finding h3 {{ margin:.2rem 0 .4rem; font-size:1.1rem; }}
.finding .meta {{ color:var(--muted); font-size:.85rem; margin:.1rem 0 .6rem; }}
footer {{ color:var(--muted); font-size:.85rem; margin-top:3rem; }}
</style></head>
<body><main>
<h1>{esc(data.title)}</h1>
<p class="meta-list">Generated {esc(data.generated_at)} · Operator {esc(data.operator)}
 · Scope {esc(data.scope_name)} · {len(data.assessments)} assessment(s)
 · {data.evidence_count} evidence item(s)</p>
<h2>Executive summary</h2><p>{esc(_summary_line(counts))}.</p>
<h2>Severity distribution</h2>
<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Methodology</h2><p>Findings were produced by authorized NXT-Security modules
({esc(', '.join(data.modules) or 'n/a')}), run only against in-scope targets.</p>
<h2>Findings</h2>{findings_html}
<footer>Generated by NXT-Security for authorized security assessment. Secrets are redacted.</footer>
</main></body></html>
"""
