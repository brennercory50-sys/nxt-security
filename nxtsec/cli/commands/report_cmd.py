"""``report``: generate a report from findings or a single assessment."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from nxtsec.cli.common import get_app
from nxtsec.core.errors import NxtSecError
from nxtsec.reporting.report import ReportData, available_formats, render_report


@click.command()
@click.option(
    "--assessment", "assessment_id", help="Report on one assessment instead of all findings."
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(available_formats(), case_sensitive=False),
    default="markdown",
    show_default=True,
)
@click.option(
    "--min-severity",
    type=click.Choice(
        [s.upper() for s in ("info", "low", "medium", "high", "critical")], case_sensitive=False
    ),
)
@click.option("--open", "open_only", is_flag=True, help="Only include OPEN/CONFIRMED findings.")
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write to a file instead of stdout.",
)
@click.option("--title", help="Override the report title.")
@click.pass_context
def report(ctx, assessment_id, fmt, min_severity, open_only, output, title):  # type: ignore[no-untyped-def]
    """Generate a professional report (markdown, html, json or csv)."""
    app = get_app(ctx)
    svc = app.findings
    if assessment_id:
        assessment = app.db.get_assessment(assessment_id)
        if assessment is None:
            raise click.ClickException(f"no such assessment: {assessment_id}")
        findings = app.db.findings_for_assessment(assessment_id)
        assessments = [assessment]
        evidence_count = len(app.db.list_evidence(assessment_id))
        default_title = f"Security assessment {assessment_id}"
    else:
        findings = svc.search()
        assessments = app.db.list_assessments(limit=1000)
        evidence_count = len(app.db.list_evidence())
        default_title = "NXT-Security findings report"

    if min_severity:
        from nxtsec.findings.service import severity_rank

        floor = severity_rank(min_severity.upper())
        findings = [f for f in findings if severity_rank(f["severity"]) >= floor]
    if open_only:
        from nxtsec.core.models import FindingStatus

        findings = [f for f in findings if FindingStatus(f["status"]).is_open]

    data = ReportData.build(
        title=title or default_title,
        operator=app.settings.operator,
        scope_name=app.load_scope().name,
        findings=findings,
        assessments=assessments,
        evidence_count=evidence_count,
    )
    try:
        rendered = render_report(data, fmt)
    except (NxtSecError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        click.echo(f"Wrote {fmt} report ({len(data.findings)} finding(s)) to {output}", err=True)
    else:
        click.echo(rendered)
    if not sys.stdout.isatty() and not output:
        return
