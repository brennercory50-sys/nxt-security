"""``scan``: plan and run assessments."""

from __future__ import annotations

import json
import sys

import click

from nxtsec.cli.commands.jobs_cmd import assessment_detail, print_detail, status_tag
from nxtsec.cli.common import get_app, json_option
from nxtsec.core.errors import NxtSecError, ScopeViolation
from nxtsec.core.models import Mode
from nxtsec.events.bus import Event
from nxtsec.jobs.runner import spawn_detached
from nxtsec.safety.redaction import redact_obj


def _parse_options(pairs: tuple[str, ...]) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in pairs:
        if "=" not in p:
            raise click.BadParameter(f"expected KEY=VALUE, got {p!r}", param_hint="-o")
        k, v = p.split("=", 1)
        out[k.strip()] = v.strip()
    return out


@click.group()
def scan() -> None:
    """Plan and run assessments against in-scope targets."""


@scan.command("run")
@click.argument("target")
@click.option(
    "-m",
    "--module",
    "modules",
    multiple=True,
    required=True,
    help="Module to run (repeatable). See `nxtsec plugins list`.",
)
@click.option(
    "-o",
    "--option",
    "options",
    multiple=True,
    metavar="KEY=VALUE",
    help="Module option, bare (ports=22,80) or namespaced " "(network.tcp_connect.ports=22).",
)
@click.option("--lab", is_flag=True, help="LAB mode: lab: targets only; enables lab-only modules.")
@click.option(
    "--queue",
    "queue_only",
    is_flag=True,
    help="Only queue it; run later with `jobs run` or `jobs worker`.",
)
@click.option("--background", is_flag=True, help="Queue it and start a detached worker process.")
@json_option
@click.pass_context
def scan_run(
    ctx: click.Context,
    target: str,
    modules: tuple[str, ...],
    options: tuple[str, ...],
    lab: bool,
    queue_only: bool,
    background: bool,
    as_json: bool,
) -> None:
    """Authorize and run MODULES against TARGET.

    Every module is checked against the scope, permission policy and risk
    limits before anything runs; any refusal aborts the whole assessment.
    Exit codes: 0 completed, 1 failed/cancelled, 3 out of scope.
    """
    app = get_app(ctx)
    try:
        a = app.engine.plan(
            target, modules, mode=Mode.LAB if lab else Mode.REAL, options=_parse_options(options)
        )
    except ScopeViolation as exc:
        click.echo(click.style(f"REFUSED: {exc}", fg="red"), err=True)
        sys.exit(3)
    except NxtSecError as exc:
        raise click.ClickException(str(exc)) from exc

    if queue_only or background:
        if background:
            pid = spawn_detached(a.id, ctx.obj.get("config"))
            msg = f"{a.id} started in background (pid {pid}). Check: nxtsec jobs show {a.id}"
        else:
            msg = f"{a.id} queued. Run: nxtsec jobs run {a.id}"
        click.echo(json.dumps({"assessment_id": a.id, "status": "queued"}) if as_json else msg)
        return

    if not as_json:
        click.echo(f"{a.id}  target={a.target.raw}  modules={','.join(a.modules)}")

        def on_module(ev: Event) -> None:
            p = ev.payload
            if p.get("assessment_id") == a.id:
                click.echo(
                    f"  {p['module']:<24} {status_tag(p['status'])} "
                    f"{p['observations']} obs, {p['findings']} findings"
                )

        app.bus.subscribe("module.finished", on_module)

    result = app.engine.execute(a.id)
    detail = assessment_detail(result.id, ctx)
    if as_json:
        click.echo(json.dumps(redact_obj(detail), indent=2, default=str))
    else:
        click.echo("")
        print_detail(detail)
    sys.exit(0 if result.status.value == "completed" else 1)
