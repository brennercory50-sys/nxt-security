"""``scope``: inspect the authorized scope."""

from __future__ import annotations

import json
import socket
import sys
from typing import Any

import click

from nxtsec.cli.common import emit, get_app, json_option
from nxtsec.core.errors import TargetError
from nxtsec.net.resolve import LookupTimeout, is_ip, resolve_host
from nxtsec.targets import parse_target


@click.group()
def scope() -> None:
    """Inspect the authorized scope."""


@scope.command("show")
@json_option
@click.pass_context
def scope_show(ctx: click.Context, as_json: bool) -> None:
    """Show the active scope: rules, expiry, attestation and fingerprint."""
    s = get_app(ctx).scope
    data = s.describe()
    data["expired"] = s.is_expired()
    emit(data, as_json)


@scope.command("check")
@click.argument("targets", nargs=-1, required=True)
@click.option(
    "--resolve",
    is_flag=True,
    help="Also resolve hostnames and verify where they point (DNS-pivot guard).",
)
@json_option
@click.pass_context
def scope_check(ctx: click.Context, targets: tuple[str, ...], resolve: bool, as_json: bool) -> None:
    """Check whether TARGETS are inside the authorized scope. Exit 3 if any is not."""
    s = get_app(ctx).scope
    results: list[dict[str, Any]] = []
    for t in targets:
        d = s.check_raw(t)
        r: dict[str, Any] = {"target": t, "allowed": d.allowed, "reason": d.reason, "rule": d.rule}
        if resolve and d.allowed:
            try:
                host = parse_target(t).host
            except TargetError:
                host = None
            if host and not is_ip(host) and "/" not in host:
                try:
                    addrs = resolve_host(host)
                except (socket.gaierror, LookupTimeout) as exc:
                    addrs = []
                    r["resolve_error"] = str(exc)
                rd = s.check_resolution(host, addrs)
                r.update(addresses=addrs, allowed=rd.allowed)
                if not rd.allowed:
                    r["reason"] = rd.reason
        results.append(r)
    if as_json:
        click.echo(json.dumps(results, indent=2))
    else:
        for r in results:
            label = "[IN SCOPE]    " if r["allowed"] else "[OUT OF SCOPE]"
            colored = click.style(label, fg="green" if r["allowed"] else "red")
            rule = f" (rule: {r['rule']})" if r["rule"] else ""
            resolved = f" -> {', '.join(r['addresses'])}" if r.get("addresses") else ""
            click.echo(f"{colored} {r['target']}{resolved}: {r['reason']}{rule}")
    if not all(r["allowed"] for r in results):
        sys.exit(3)
