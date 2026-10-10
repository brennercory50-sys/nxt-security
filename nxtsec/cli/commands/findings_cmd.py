"""``findings``: triage findings across all assessments."""

from __future__ import annotations

import json

import click

from nxtsec.cli.common import get_app, json_option
from nxtsec.core.errors import NxtSecError
from nxtsec.core.models import FindingStatus, Severity
from nxtsec.safety.redaction import redact, redact_obj

SEVERITIES = [s.value for s in Severity]
STATUSES = [s.value for s in FindingStatus]
SEV_COLOR = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "cyan"}


def sev_tag(sev: str) -> str:
    return click.style(f"{sev:<8}", fg=SEV_COLOR.get(sev))


@click.group()
def findings() -> None:
    """List, triage and export findings."""


@findings.command("list")
@click.option("--status", type=click.Choice(STATUSES, case_sensitive=False))
@click.option("--min-severity", type=click.Choice(SEVERITIES, case_sensitive=False))
@click.option("--module", help="Only findings from this detection module.")
@click.option("--open", "open_only", is_flag=True, help="Only OPEN/CONFIRMED findings.")
@json_option
@click.pass_context
def findings_list(ctx, status, min_severity, module, open_only, as_json):  # type: ignore[no-untyped-def]
    """List findings, most severe first."""
    svc = get_app(ctx).findings
    rows = svc.search(status=status, min_severity=min_severity, open_only=open_only, module=module)
    if as_json:
        click.echo(json.dumps(redact_obj(rows), indent=2, default=str))
        return
    if not rows:
        click.echo("No findings match.")
        return
    for f in rows:
        click.echo(
            f"{f['id']}  {sev_tag(f['severity'])} {f['status']:<14} "
            f"{redact(f['title'])}  [{f.get('detection_module', '')}]"
        )
    counts = svc.summary(rows)
    click.echo("\n" + "  ".join(f"{k}:{v}" for k, v in counts.items() if v))


@findings.command("show")
@click.argument("ref")
@json_option
@click.pass_context
def findings_show(ctx, ref, as_json):  # type: ignore[no-untyped-def]
    """Show one finding in full (accepts an id or unique id prefix)."""
    svc = get_app(ctx).findings
    try:
        f = svc.resolve(ref)
    except NxtSecError as exc:
        raise click.ClickException(str(exc)) from exc
    if as_json:
        click.echo(json.dumps(redact_obj(f), indent=2, default=str))
        return
    click.echo(f"{click.style(f['id'], bold=True)}  {sev_tag(f['severity'])} {f['status']}")
    click.echo(f"  {redact(f['title'])}")
    for label, key in (
        ("Target", "target"),
        ("Component", "component"),
        ("Module", "detection_module"),
        ("CWE", "cwe"),
        ("Confidence", "confidence"),
    ):
        if f.get(key):
            click.echo(f"  {label}: {redact(str(f[key]))}")
    for label, key in (
        ("Description", "description"),
        ("Impact", "impact"),
        ("Remediation", "remediation"),
    ):
        if f.get(key):
            click.echo(f"\n  {label}:\n    {redact(f[key])}")
    if f.get("references"):
        click.echo("\n  References:")
        for r in f["references"]:
            click.echo(f"    - {redact(r)}")
    if f.get("evidence_ids"):
        click.echo(f"\n  Evidence: {', '.join(f['evidence_ids'])}")
    for note in f.get("notes", []):
        click.echo(f"\n  note {note['at']} ({redact(note['by'])}): {redact(note['text'])}")


@findings.command("set-status")
@click.argument("ref")
@click.argument("status", type=click.Choice(STATUSES, case_sensitive=False))
@click.option("--note", help="Optional note recorded with the change.")
@click.pass_context
def findings_set_status(ctx, ref, status, note):  # type: ignore[no-untyped-def]
    """Change a finding's status (validated state machine)."""
    svc = get_app(ctx).findings
    try:
        f = svc.set_status(ref, status, note)
    except NxtSecError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{f['id']} -> {f['status']}")


@findings.command("note")
@click.argument("ref")
@click.argument("text")
@click.pass_context
def findings_note(ctx, ref, text):  # type: ignore[no-untyped-def]
    """Attach a note to a finding."""
    svc = get_app(ctx).findings
    try:
        svc.add_note(ref, text)
    except NxtSecError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("note added")


@findings.command("stats")
@json_option
@click.pass_context
def findings_stats(ctx, as_json):  # type: ignore[no-untyped-def]
    """Severity and status breakdown across all findings."""
    svc = get_app(ctx).findings
    allf = svc.search()
    by_status: dict[str, int] = {s: 0 for s in STATUSES}
    for f in allf:
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
    by_severity = svc.summary(allf)
    if as_json:
        click.echo(
            json.dumps(
                {"total": len(allf), "by_severity": by_severity, "by_status": by_status}, indent=2
            )
        )
        return
    click.echo(f"Total: {len(allf)}")
    click.echo("Severity: " + "  ".join(f"{k}:{v}" for k, v in by_severity.items()))
    click.echo("Status:   " + "  ".join(f"{k}:{v}" for k, v in by_status.items() if v))
