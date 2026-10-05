"""Shared CLI helpers: lazy App construction, output, status tags."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, TypeVar

import click
import yaml

from nxtsec.core.app import App
from nxtsec.core.errors import NxtSecError
from nxtsec.safety.redaction import redact_obj

F = TypeVar("F", bound=Callable[..., Any])

TAG_COLORS = {
    "OK": "green",
    "INSTALLED": "green",
    "WARN": "yellow",
    "OUTDATED": "yellow",
    "MISSING": "yellow",
    "UNSUPPORTED": "blue",
    "ERROR": "red",
    "BROKEN": "red",
    "READY": "green",
    "DEGRADED": "yellow",
    "NOT READY": "red",
}


def get_app(ctx: click.Context) -> App:
    obj: dict[str, Any] = ctx.ensure_object(dict)
    if "app" not in obj:
        try:
            obj["app"] = App.create(obj.get("config"), log_to_file=not obj.get("no_log_file"))
        except NxtSecError as exc:
            raise click.ClickException(str(exc)) from exc
    app: App = obj["app"]
    return app


def emit(data: Any, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(redact_obj(data), indent=2, default=str))
    else:
        click.echo(yaml.safe_dump(redact_obj(data), sort_keys=False).rstrip())


def tag(level: str, width: int = 0) -> str:
    text = f"[{level}]".ljust(width)
    return click.style(text, fg=TAG_COLORS.get(level))


def json_option(f: F) -> F:
    return click.option("--json", "as_json", is_flag=True, help="Machine-readable JSON output.")(f)
