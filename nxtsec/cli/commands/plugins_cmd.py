"""``plugins``: list registered plugins."""

from __future__ import annotations

import json

import click

from nxtsec.cli.common import get_app, json_option


@click.group()
def plugins() -> None:
    """List and inspect plugins."""


@plugins.command("list")
@json_option
@click.pass_context
def plugins_list(ctx: click.Context, as_json: bool) -> None:
    """List registered plugins and their declared permissions."""
    reg = get_app(ctx).plugins
    data = [m.to_dict() for m in reg.manifests()]
    if as_json:
        click.echo(json.dumps({"plugins": data, "errors": reg.load_errors}, indent=2))
        return
    if not data:
        click.echo("No plugins registered yet.")
    for m in data:
        click.echo(
            f"{m['name']:<24} {m['version']:<8} {m['risk_level']:<8} "
            f"{','.join(m['permissions'])}"
        )
    for name, err in reg.load_errors.items():
        click.echo(f"[ERROR] {name}: {err}")
