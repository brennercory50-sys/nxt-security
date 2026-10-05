"""``tools``: the external tool registry."""

from __future__ import annotations

import json
import sys

import click

from nxtsec.cli.common import get_app, json_option, tag
from nxtsec.integrations.tools import ToolStatus


@click.group(invoke_without_command=True)
@click.pass_context
def tools(ctx: click.Context) -> None:
    """External tools NXT-Security can integrate with. Defaults to ``tools check``."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(tools_check)


@tools.command("list")
@json_option
@click.pass_context
def tools_list(ctx: click.Context, as_json: bool) -> None:
    """List known tools and their metadata (no detection)."""
    specs = get_app(ctx).tools.specs()
    if as_json:
        click.echo(json.dumps([s.to_dict() for s in specs], indent=2))
        return
    for s in specs:
        req = "required" if s.required else "optional"
        click.echo(
            f"{s.name:<10} {s.category:<10} {req:<9} {s.risk_level.value:<8} " f"{s.description}"
        )


@tools.command("check")
@click.argument("names", nargs=-1)
@json_option
@click.pass_context
def tools_check(ctx: click.Context, names: tuple[str, ...], as_json: bool = False) -> None:
    """Detect tools: INSTALLED, MISSING, OUTDATED, BROKEN or UNSUPPORTED.

    Nothing is ever installed. Exit 1 if a required tool is not INSTALLED.
    """
    reg = get_app(ctx).tools
    try:
        states = [reg.check(n) for n in names] if names else reg.check_all()
    except KeyError as exc:
        raise click.ClickException(str(exc.args[0])) from exc
    if as_json:
        click.echo(json.dumps([s.to_dict() for s in states], indent=2))
    else:
        for s in states:
            ver = s.version or ""
            click.echo(
                f"{s.spec.name:<10} {tag(s.status.value, 14)} {ver:<10} " f"{s.path or s.detail}"
            )
    if any(s.spec.required and s.status != ToolStatus.INSTALLED for s in states):
        sys.exit(1)


@tools.command("info")
@click.argument("name")
@click.pass_context
def tools_info(ctx: click.Context, name: str) -> None:
    """Show metadata and install instructions for one tool."""
    reg = get_app(ctx).tools
    try:
        spec = reg.get(name)
    except KeyError as exc:
        raise click.ClickException(str(exc.args[0])) from exc
    st = reg.check(name)
    d = spec.to_dict()
    d["status"] = st.status.value
    d["detected_path"] = st.path
    d["detected_version"] = st.version
    click.echo(json.dumps(d, indent=2))
