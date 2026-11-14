"""``ai``: advisory AI analysis of findings (provider-agnostic)."""

from __future__ import annotations

import json

import click

from nxtsec.ai.analyst import ADVISORY_BANNER
from nxtsec.ai.base import AIError
from nxtsec.cli.common import get_app, json_option
from nxtsec.core.errors import NxtSecError
from nxtsec.safety.redaction import redact


@click.group()
def ai() -> None:
    """AI-assisted analysis. Output is advisory and never changes a finding."""


@ai.command("status")
@json_option
@click.pass_context
def ai_status(ctx: click.Context, as_json: bool) -> None:
    """Show the configured AI provider and whether it is ready to use."""
    app = get_app(ctx)
    info = app.ai_provider.describe()
    if as_json:
        click.echo(json.dumps(info, indent=2))
        return
    tag = (
        click.style("ready", fg="green") if info["ready"] else click.style("not ready", fg="yellow")
    )
    click.echo(f"provider: {info['provider']}  model: {info['model']}  [{tag}]")
    click.echo(f"  {info['detail']}")
    if info["provider"] == "offline":
        click.echo(
            "  Set ai.provider (claude|openai|local) and the key env var for richer analysis."
        )


@ai.command("analyze")
@click.argument("ref")
@click.option("--annotate", is_flag=True, help="Attach the analysis to the finding as a note.")
@json_option
@click.pass_context
def ai_analyze(ctx: click.Context, ref: str, annotate: bool, as_json: bool) -> None:
    """Analyze one finding (id or prefix): risk, true/false-positive view, remediation."""
    app = get_app(ctx)
    try:
        resp = app.ai.analyze_finding(ref, annotate=annotate)
    except NxtSecError as exc:
        raise click.ClickException(str(exc)) from exc
    _emit(resp, as_json)
    if annotate and not as_json:
        click.echo(click.style("\n(attached to the finding as a note)", fg="cyan"))


@ai.command("summarize")
@click.option("--min-severity", help="Only summarize findings at or above this severity.")
@click.option("--open", "open_only", is_flag=True, help="Only OPEN/CONFIRMED findings.")
@json_option
@click.pass_context
def ai_summarize(
    ctx: click.Context, min_severity: str | None, open_only: bool, as_json: bool
) -> None:
    """Write a short, prioritized AI summary across findings."""
    app = get_app(ctx)
    findings = app.findings.search(min_severity=min_severity, open_only=open_only)
    if not findings:
        click.echo("No findings to summarize.")
        return
    try:
        resp = app.ai.summarize(findings)
    except AIError as exc:
        raise click.ClickException(str(exc)) from exc
    _emit(resp, as_json)


def _emit(resp, as_json: bool) -> None:  # type: ignore[no-untyped-def]
    if as_json:
        click.echo(
            json.dumps(
                {
                    "provider": resp.provider,
                    "model": resp.model,
                    "truncated": resp.truncated,
                    "usage": resp.usage,
                    "text": redact(resp.text),
                },
                indent=2,
            )
        )
        return
    click.echo(click.style(f"{ADVISORY_BANNER} [{resp.provider}/{resp.model}]", fg="cyan"))
    click.echo(redact(resp.text))
    if resp.truncated:
        click.echo(click.style("\n(response was truncated — raise max_tokens)", fg="yellow"))
