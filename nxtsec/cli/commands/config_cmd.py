"""``config``: inspect and initialize configuration."""

from __future__ import annotations

import shutil

import click

from nxtsec.cli.common import emit, get_app, json_option
from nxtsec.core.errors import NxtSecError


@click.group()
def config() -> None:
    """Inspect, validate and initialize configuration."""


@config.command("show")
@json_option
@click.pass_context
def config_show(ctx: click.Context, as_json: bool) -> None:
    """Print the effective (merged, redacted) configuration."""
    s = get_app(ctx).settings
    emit(
        {
            "sources": s.sources,
            "home": str(s.home),
            "database": s.database_url,
            "scope_file": str(s.scope_file),
            "settings": s.data,
        },
        as_json,
    )


@config.command("path")
@click.pass_context
def config_path(ctx: click.Context) -> None:
    """Print the important file locations."""
    s = get_app(ctx).settings
    for k, v in (
        ("project", s.project_root),
        ("home", s.home),
        ("scope", s.scope_file),
        ("database", s.database_url),
        ("logs", s.log_dir),
    ):
        click.echo(f"{k:<9} {v}")


@config.command("validate")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate configuration and the scope file."""
    app = get_app(ctx)
    try:
        scope = app.scope
    except NxtSecError as exc:
        raise click.ClickException(f"scope: {exc}") from exc
    click.echo(f"[OK] configuration ({', '.join(app.settings.sources)})")
    if app.settings.scope_file.is_file():
        click.echo(
            f"[OK] scope '{scope.name}' ({len(scope.allow_entries)} allow, "
            f"{len(scope.deny_entries)} deny)"
        )
    else:
        click.echo(
            f"[WARN] no scope file at {app.settings.scope_file}: all network targets "
            "will be refused"
        )


@config.command("init-scope")
@click.option("--force", is_flag=True, help="Overwrite an existing scope file.")
@click.pass_context
def config_init_scope(ctx: click.Context, force: bool) -> None:
    """Create the scope file from config/scope.example.yaml."""
    s = get_app(ctx).settings
    src = s.project_root / "config" / "scope.example.yaml"
    dst = s.scope_file
    if dst.exists() and not force:
        raise click.ClickException(f"{dst} already exists (use --force to overwrite)")
    if not src.is_file():
        raise click.ClickException(f"template not found: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    click.echo(f"Created {dst}. Edit it to list ONLY systems you are authorized to test.")
