"""``version`` and ``doctor``."""

from __future__ import annotations

import json
import sys

import click

from nxtsec import __version__
from nxtsec.cli.common import get_app, json_option, tag
from nxtsec.core.doctor import Doctor, Level
from nxtsec.platform.detect import detect_platform


@click.command()
@json_option
def version(as_json: bool) -> None:
    """Show NXT-Security and platform version information."""
    p = detect_platform()
    data = {
        "nxtsec": __version__,
        "python": p.python,
        "platform": p.label,
        "release": p.release,
        "machine": p.machine,
    }
    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(f"nxtsec {__version__} (Python {p.python}, {p.label} {p.machine})")


@click.command()
@json_option
@click.option("--strict", is_flag=True, help="Exit non-zero on DEGRADED as well as NOT READY.")
@click.pass_context
def doctor(ctx: click.Context, as_json: bool, strict: bool) -> None:
    """Inspect the platform, tools, configuration, database and plugins.

    Exit code: 0 READY/DEGRADED, 1 NOT READY (or DEGRADED with --strict).
    """
    app = get_app(ctx)
    report = Doctor(app.settings, app.platform, app.tools, lambda: app.plugins).run()
    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        click.echo(click.style("NXT-SECURITY SYSTEM CHECK", bold=True))
        click.echo("=" * 25)
        section = None
        order = {"system": 0, "network": 1, "config": 2, "tools": 3}
        for c in sorted(report.checks, key=lambda c: order.get(c.section, 9)):
            if c.section != section:
                section = c.section
                click.echo(f"\n{section.upper()}")
            click.echo(f"  {c.name:<24} {tag(c.level.value, 10)} {c.detail}")
        color = {"READY": "green", "DEGRADED": "yellow"}.get(report.overall, "red")
        click.echo(f"\nOverall: {click.style(report.overall, fg=color, bold=True)}")
    failed = report.overall == "NOT READY" or (strict and report.overall != "READY")
    if failed:
        sys.exit(1)


__all__ = ["Level", "doctor", "version"]
