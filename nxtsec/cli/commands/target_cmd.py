"""``target``: parse, save and list targets."""

from __future__ import annotations

import json

import click

from nxtsec.cli.common import get_app, json_option
from nxtsec.core.errors import TargetError
from nxtsec.targets import parse_target


@click.group()
def target() -> None:
    """Parse, save and list assessment targets."""


@target.command("parse")
@click.argument("raw")
@click.pass_context
def target_parse(ctx: click.Context, raw: str) -> None:
    """Show how RAW is classified and whether it is in scope."""
    try:
        t = parse_target(raw)
    except TargetError as exc:
        raise click.ClickException(str(exc)) from exc
    d = get_app(ctx).scope.check(t)
    click.echo(
        json.dumps({**t.to_dict(), "in_scope": d.allowed, "scope_reason": d.reason}, indent=2)
    )


@target.command("add")
@click.argument("raw")
@click.option("--label", help="Optional human-readable label.")
@click.option(
    "--allow-out-of-scope",
    is_flag=True,
    help="Save even if out of scope (it still cannot be scanned).",
)
@click.pass_context
def target_add(ctx: click.Context, raw: str, label: str | None, allow_out_of_scope: bool) -> None:
    """Save a target to the inventory. Out-of-scope targets are refused by default."""
    app = get_app(ctx)
    try:
        t = parse_target(raw)
    except TargetError as exc:
        raise click.ClickException(str(exc)) from exc
    d = app.scope.check(t)
    if not d.allowed and not allow_out_of_scope:
        raise click.ClickException(f"{raw!r} is out of scope ({d.reason})")
    tid, created = app.db.add_target(t, label)
    app.db.audit(app.settings.operator, "target.add", t.value, {"created": created})
    click.echo(f"{'Added' if created else 'Already saved'}: {tid} {t.type.value} {t.value}")


@target.command("list")
@json_option
@click.pass_context
def target_list(ctx: click.Context, as_json: bool) -> None:
    """List saved targets with their current scope status."""
    app = get_app(ctx)
    rows = app.db.list_targets()
    for r in rows:
        r["in_scope"] = app.scope.check_raw(r["raw"]).allowed
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No saved targets. Add one with: nxtsec target add <target>")
    for r in rows:
        flag = (
            click.style("in-scope ", fg="green")
            if r["in_scope"]
            else click.style("OUT-SCOPE", fg="red")
        )
        click.echo(f"{r['id']}  {flag}  {r['type']:<8} {r['value']}  {r['label'] or ''}")


@target.command("remove")
@click.argument("ref")
@click.pass_context
def target_remove(ctx: click.Context, ref: str) -> None:
    """Remove a saved target by ID or value."""
    app = get_app(ctx)
    if not app.db.remove_target(ref):
        raise click.ClickException(f"no saved target matches {ref!r}")
    app.db.audit(app.settings.operator, "target.remove", ref, {})
    click.echo(f"Removed {ref}")
