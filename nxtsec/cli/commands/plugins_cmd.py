"""``plugins``: list and inspect registered plugins."""

from __future__ import annotations

import inspect
import json

import click

from nxtsec.cli.common import get_app, json_option
from nxtsec.core.errors import PluginError


@click.group()
def plugins() -> None:
    """List and inspect plugins."""


@plugins.command("list")
@json_option
@click.pass_context
def plugins_list(ctx: click.Context, as_json: bool) -> None:
    """List registered plugins, their target types and declared permissions."""
    reg = get_app(ctx).plugins
    data = [m.to_dict() for m in reg.manifests()]
    if as_json:
        click.echo(json.dumps({"plugins": data, "errors": reg.load_errors}, indent=2))
        return
    if not data:
        click.echo("No plugins registered yet.")
    else:
        click.echo(f"{'NAME':<22} {'VERSION':<8} {'RISK':<8} {'TARGETS':<34} PERMISSIONS")
    for m in data:
        targets = ",".join(m["target_types"]) or "-"
        click.echo(
            f"{m['name']:<22} {m['version']:<8} {m['risk_level']:<8} {targets:<34} "
            f"{','.join(m['permissions'])}"
        )
    for name, err in reg.load_errors.items():
        click.echo(f"[ERROR] {name}: {err}")


@plugins.command("show")
@click.argument("name")
@click.pass_context
def plugins_show(ctx: click.Context, name: str) -> None:
    """Show one plugin's manifest and documentation."""
    try:
        cls = get_app(ctx).plugins.get(name)
    except PluginError as exc:
        raise click.ClickException(str(exc)) from exc
    data = cls.manifest.to_dict()
    module = inspect.getmodule(cls)
    data["documentation"] = inspect.cleandoc(module.__doc__ or "") if module else ""
    click.echo(json.dumps(data, indent=2))
