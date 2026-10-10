"""``recon``: convenience front-end over the assessment engine for passive recon.

``nxtsec recon dns example.com`` is shorthand for planning and running the
``dns.records`` and ``ip.info`` modules and printing the normalized result.
Everything still flows through the engine, so scope, attestation and auditing
all apply exactly as with ``nxtsec scan run``.
"""

from __future__ import annotations

import json
import sys

import click

from nxtsec.cli.commands.jobs_cmd import assessment_detail, print_detail
from nxtsec.cli.common import get_app, json_option
from nxtsec.core.errors import NxtSecError, ScopeViolation
from nxtsec.core.models import Mode
from nxtsec.safety.redaction import redact_obj

RECON_PROFILES = {
    "dns": ["dns.records", "ip.info"],
    "ip": ["ip.info"],
}


def _run(ctx: click.Context, target: str, modules: list[str], as_json: bool) -> None:
    app = get_app(ctx)
    try:
        a = app.engine.plan(target, modules, mode=Mode.REAL)
    except ScopeViolation as exc:
        click.echo(click.style(f"REFUSED: {exc}", fg="red"), err=True)
        sys.exit(3)
    except NxtSecError as exc:
        raise click.ClickException(str(exc)) from exc
    result = app.engine.execute(a.id)
    detail = assessment_detail(result.id, ctx)
    if as_json:
        click.echo(json.dumps(redact_obj(detail), indent=2, default=str))
    else:
        print_detail(detail)
    sys.exit(0 if result.status.value == "completed" else 1)


@click.group()
def recon() -> None:
    """Passive, authorized reconnaissance (runs through the assessment engine)."""


@recon.command("dns")
@click.argument("target")
@json_option
@click.pass_context
def recon_dns(ctx: click.Context, target: str, as_json: bool) -> None:
    """Enumerate DNS records, mail-security posture and IP classification for TARGET."""
    _run(ctx, target, RECON_PROFILES["dns"], as_json)


@recon.command("ip")
@click.argument("target")
@json_option
@click.pass_context
def recon_ip(ctx: click.Context, target: str, as_json: bool) -> None:
    """Classify TARGET's addresses and resolve their PTR records."""
    _run(ctx, target, RECON_PROFILES["ip"], as_json)
