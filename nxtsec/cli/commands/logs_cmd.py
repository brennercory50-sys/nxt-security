"""``logs``: read the structured log file."""

from __future__ import annotations

import json
from collections import deque

import click

from nxtsec.cli.common import get_app

LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


@click.command()
@click.option("-n", "--lines", default=50, show_default=True, type=click.IntRange(1, 100000))
@click.option(
    "--level", type=click.Choice(LEVELS, case_sensitive=False), help="Minimum severity to show."
)
@click.option("--assessment", "assessment_id", help="Only entries for this assessment ID.")
@click.option("--raw", is_flag=True, help="Print raw JSON lines.")
@click.pass_context
def logs(
    ctx: click.Context, lines: int, level: str | None, assessment_id: str | None, raw: bool
) -> None:
    """Show recent entries from the NXT-Security log file (already redacted)."""
    path = get_app(ctx).settings.log_dir / "nxtsec.jsonl"
    if not path.is_file():
        click.echo(f"No log file yet at {path}")
        return
    min_rank = LEVELS.index(level.upper()) if level else 0
    keep: deque[str] = deque(maxlen=lines)
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if assessment_id and rec.get("assessment_id") != assessment_id:
                continue
            sev = str(rec.get("severity", "INFO"))
            if sev in LEVELS and LEVELS.index(sev) < min_rank:
                continue
            if raw:
                keep.append(line.rstrip())
                continue
            module = f" [{rec['module']}]" if rec.get("module") else ""
            keep.append(
                f"{rec.get('timestamp', '')} {sev:<8} {rec.get('logger', '')}: "
                f"{rec.get('message', '')}{module}"
            )
    for item in keep:
        click.echo(item)
