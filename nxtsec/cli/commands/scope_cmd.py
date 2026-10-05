"""``scope``: inspect the authorized scope."""

from __future__ import annotations

import json
import sys

import click

from nxtsec.cli.common import emit, get_app, json_option


@click.group()
def scope() -> None:
    """Inspect the authorized scope."""


@scope.command("show")
@json_option
@click.pass_context
def scope_show(ctx: click.Context, as_json: bool) -> None:
    """Show the active scope definition."""
    s = get_app(ctx).scope
    emit(
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
@json_option
@click.pass_context
def scope_check(ctx: click.Context, targets: tuple[str, ...], as_json: bool) -> None:
    """Check whether TARGETS are inside the authorized scope. Exit 3 if any is not."""
    s = get_app(ctx).scope
    results = []
    for t in targets:
        d = s.check_raw(t)
        results.append({"target": t, "allowed": d.allowed, "reason": d.reason, "rule": d.rule})
    if as_json:
        click.echo(json.dumps(results, indent=2))
    else:
        for r in results:
            label = "[IN SCOPE]    " if r["allowed"] else "[OUT OF SCOPE]"
            colored = click.style(label, fg="green" if r["allowed"] else "red")
            rule = f" (rule: {r['rule']})" if r["rule"] else ""
            click.echo(f"{colored} {r['target']}: {r['reason']}{rule}")
    if not all(r["allowed"] for r in results):
        sys.exit(3)
