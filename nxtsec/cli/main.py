"""``nxtsec`` command-line entry point.

Phase 1 ships the foundation commands. Later phases add ``doctor``, ``tools``,
``scan``, ``recon`` and the rest under the same group.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from nxtsec import __version__
from nxtsec.core.app import App
from nxtsec.core.errors import NxtSecError
from nxtsec.platform.detect import detect_platform
from nxtsec.safety.redaction import redact_obj


def _app(ctx: click.Context) -> App:
    obj: dict[str, Any] = ctx.ensure_object(dict)
    if "app" not in obj:
        try:
            obj["app"] = App.create(obj.get("config"), log_to_file=not obj.get("no_log_file"))
        except NxtSecError as exc:
            raise click.ClickException(str(exc)) from exc
    app: App = obj["app"]
    return app


def _emit(data: Any, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(redact_obj(data), indent=2, default=str))
    else:
        click.echo(yaml.safe_dump(redact_obj(data), sort_keys=False).rstrip())


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config",
    "config",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Path to an alternate config.yaml.",
)
@click.option("--no-log-file", is_flag=True, help="Do not write the rotating JSON log file.")
@click.version_option(__version__, "-V", "--version", prog_name="nxtsec")
@click.pass_context
def cli(ctx: click.Context, config: Path | None, no_log_file: bool) -> None:
    """NXT-Security: authorized security research platform.

    Only operate against systems you own or are explicitly authorized to test.
    """
    ctx.ensure_object(dict).update(config=config, no_log_file=no_log_file)


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
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


@cli.group()
def config() -> None:
    """Inspect and validate configuration."""


@config.command("show")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.pass_context
def config_show(ctx: click.Context, as_json: bool) -> None:
    """Print the effective (merged, redacted) configuration."""
    s = _app(ctx).settings
    _emit(
        {
            "sources": s.sources,
            "home": str(s.home),
            "database": s.database_url,
            "scope_file": str(s.scope_file),
            "settings": s.data,
        },
        as_json,
    )


@config.command("validate")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate configuration and the scope file."""
    app = _app(ctx)
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


@cli.group()
def scope() -> None:
    """Inspect the authorized scope."""


@scope.command("show")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def scope_show(ctx: click.Context, as_json: bool) -> None:
    """Show the active scope definition."""
    s = _app(ctx).scope
    _emit(
        {
            "name": s.name,
            "attestation": s.attestation,
            "allow": s.allow_entries,
            "deny": s.deny_entries,
        },
        as_json,
    )


@scope.command("check")
@click.argument("targets", nargs=-1, required=True)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def scope_check(ctx: click.Context, targets: tuple[str, ...], as_json: bool) -> None:
    """Check whether TARGETS are inside the authorized scope. Exit 3 if any is not."""
    s = _app(ctx).scope
    results = []
    for t in targets:
        d = s.check_raw(t)
        results.append({"target": t, "allowed": d.allowed, "reason": d.reason, "rule": d.rule})
    if as_json:
        click.echo(json.dumps(results, indent=2))
    else:
        for r in results:
            tag = "[IN SCOPE]    " if r["allowed"] else "[OUT OF SCOPE]"
            rule = f" (rule: {r['rule']})" if r["rule"] else ""
            click.echo(f"{tag} {r['target']}: {r['reason']}{rule}")
    if not all(r["allowed"] for r in results):
        sys.exit(3)


@cli.group()
def plugins() -> None:
    """List and manage plugins."""


@plugins.command("list")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def plugins_list(ctx: click.Context, as_json: bool) -> None:
    """List registered plugins and their declared permissions."""
    reg = _app(ctx).plugins
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


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
