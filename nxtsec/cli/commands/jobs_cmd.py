"""``jobs``: inspect and control assessment jobs."""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import click

from nxtsec.cli.common import get_app, json_option
from nxtsec.core.errors import JobError
from nxtsec.evidence.store import EvidenceStore
from nxtsec.safety.redaction import redact_obj

STATUS_COLORS = {
    "queued": "blue",
    "running": "cyan",
    "completed": "green",
    "failed": "red",
    "cancelled": "yellow",
}
_STATUSES = list(STATUS_COLORS)


def status_tag(status: str) -> str:
    return click.style(f"{status:<9}", fg=STATUS_COLORS.get(status))


def assessment_detail(assessment_id: str, ctx: click.Context) -> dict[str, Any]:
    app = get_app(ctx)
    a = app.db.get_assessment(assessment_id)
    if a is None:
        raise click.ClickException(f"no such assessment: {assessment_id}")
    evidence = app.db.list_evidence(assessment_id)
    for ev in evidence:
        ev["verified"] = EvidenceStore.verify(ev)
    return {
        "assessment": a,
        "module_runs": app.db.list_module_runs(assessment_id),
        "findings": app.db.findings_for_assessment(assessment_id),
        "evidence": evidence,
    }


def _obs_line(o: dict[str, Any]) -> str:
    t = o.get("type", "?")
    if t == "tcp.port":
        return f"{o['address']}:{o['port']:<6} {o['state']:<11} {o.get('latency_ms', '')}ms"
    if t == "dns.address":
        return f"{o['name']} {o['record']:<4} {o['address']}"
    if t == "dns.ptr":
        return f"{o['address']} PTR {', '.join(o['names'])}"
    if t == "file.hash":
        return f"{o['sha256']}  {o['path']} ({o['size']} bytes)"
    return json.dumps({k: v for k, v in o.items() if k != "type"}, default=str)


def print_detail(detail: dict[str, Any], max_obs: int = 50) -> None:
    detail = redact_obj(detail)
    a = detail["assessment"]
    click.echo(
        f"{click.style(a['id'], bold=True)}  {status_tag(a['status'])} "
        f"{a['mode'].upper()}  target={a['target']['raw']}"
    )
    click.echo(
        f"  operator={a['operator']}  scope={a['scope_name']} "
        f"({(a.get('scope_fingerprint') or '')[:12]})"
    )
    click.echo(
        f"  created={a['created_at']}  started={a.get('started_at') or '-'}  "
        f"finished={a.get('finished_at') or '-'}"
    )
    if a.get("options"):
        click.echo(f"  options={a['options']}")
    if a.get("error"):
        click.echo(click.style(f"  error: {a['error']}", fg="red"))
    for run in detail["module_runs"]:
        click.echo(
            f"\n  [{run['module']}] {status_tag(run['status'])} "
            f"{run['observation_count']} observation(s), "
            f"{run['finding_count']} finding(s)"
        )
        if run.get("error"):
            click.echo(click.style(f"    error: {run['error']}", fg="red"))
        for e in run.get("errors", []):
            click.echo(click.style(f"    note: {e}", fg="yellow"))
        for o in run.get("observations", [])[:max_obs]:
            click.echo(f"    {_obs_line(o)}")
        hidden = len(run.get("observations", [])) - max_obs
        if hidden > 0:
            click.echo(f"    ... {hidden} more (use --json)")
    pending = [m for m in a["modules"] if m not in {r["module"] for r in detail["module_runs"]}]
    if pending and a["status"] in ("queued", "running"):
        click.echo(f"\n  pending: {', '.join(pending)}")
    if detail["findings"]:
        click.echo("\n  Findings:")
        for f in detail["findings"]:
            click.echo(f"    {f['severity']:<8} {f['title']}  ({f['id']})")
    if detail["evidence"]:
        ok = sum(e["verified"] for e in detail["evidence"])
        click.echo(f"\n  Evidence: {len(detail['evidence'])} item(s), {ok} verified intact")


@click.group()
def jobs() -> None:
    """Inspect and control assessment jobs (queued, running, finished)."""


@jobs.command("list")
@click.option("--status", type=click.Choice(_STATUSES), help="Only show this status.")
@click.option("--limit", default=20, show_default=True, type=click.IntRange(1, 1000))
@json_option
@click.pass_context
def jobs_list(ctx: click.Context, status: str | None, limit: int, as_json: bool) -> None:
    """List recent assessments."""
    rows = get_app(ctx).db.list_assessments(limit=limit, status=status)
    if as_json:
        click.echo(json.dumps(redact_obj(rows), indent=2))
        return
    if not rows:
        click.echo("No assessments yet. Start one with: nxtsec scan run <target> -m <module>")
    for a in rows:
        click.echo(
            f"{a['id']}  {status_tag(a['status'])} {a['created_at'][:19]}  "
            f"{a['target']['raw']:<28} {','.join(a['modules'])}"
        )


@jobs.command("show")
@click.argument("assessment_id")
@json_option
@click.pass_context
def jobs_show(ctx: click.Context, assessment_id: str, as_json: bool) -> None:
    """Show an assessment with its module runs, findings and evidence."""
    detail = assessment_detail(assessment_id, ctx)
    if as_json:
        click.echo(json.dumps(redact_obj(detail), indent=2, default=str))
    else:
        print_detail(detail)


@jobs.command("cancel")
@click.argument("assessment_id")
@click.pass_context
def jobs_cancel(ctx: click.Context, assessment_id: str) -> None:
    """Cancel a queued assessment, or request a running one to stop."""
    try:
        outcome = get_app(ctx).engine.cancel(assessment_id)
    except JobError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{assessment_id}: {outcome}")


@jobs.command("run")
@click.argument("assessment_id")
@json_option
@click.pass_context
def jobs_run(ctx: click.Context, assessment_id: str, as_json: bool) -> None:
    """Execute a queued assessment in the foreground."""
    app = get_app(ctx)
    try:
        a = app.engine.execute(assessment_id)
    except JobError as exc:
        raise click.ClickException(str(exc)) from exc
    detail = assessment_detail(a.id, ctx)
    if as_json:
        click.echo(json.dumps(redact_obj(detail), indent=2, default=str))
    else:
        print_detail(detail)
    sys.exit(0 if a.status.value == "completed" else 1)


@jobs.command("worker")
@click.option("--once", is_flag=True, help="Drain the current queue, then exit.")
@click.option(
    "--poll",
    type=click.FloatRange(0.5, 3600),
    default=None,
    help="Seconds between queue checks (default: jobs.poll_interval).",
)
@click.option(
    "--max-jobs",
    type=click.IntRange(1),
    default=None,
    help="Exit after running this many assessments.",
)
@click.pass_context
def jobs_worker(ctx: click.Context, once: bool, poll: float | None, max_jobs: int | None) -> None:
    """Run queued assessments as they arrive (Ctrl+C to stop)."""
    app = get_app(ctx)
    interval = poll or float(app.settings.get("jobs.poll_interval", 5))
    done = 0
    click.echo(f"worker started (poll={interval}s)")
    try:
        while True:
            remaining = None if max_jobs is None else max_jobs - done
            for a in app.engine.run_queued(limit=remaining):
                done += 1
                click.echo(f"{a.id}  {status_tag(a.status.value)} {a.target.raw}")
            if once or (max_jobs is not None and done >= max_jobs):
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        click.echo("\nworker stopped")
    click.echo(f"{done} assessment(s) processed")
