"""Logging configuration: console, JSON and rotating file handlers.

Every handler passes through :class:`RedactionFilter`, so secrets cannot
reach any log sink even if a module logs them by mistake.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nxtsec.safety.redaction import redact, redact_obj

CONTEXT_FIELDS = ("event", "module", "assessment_id", "target", "command", "returncode")
_STD = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        for k, v in list(vars(record).items()):
            if k not in _STD:
                setattr(record, k, redact_obj(v))
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for k, v in vars(record).items():
            if k not in _STD:
                out[k] = v
        if record.exc_info:
            out["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(out, default=str)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ctx = " ".join(f"{k}={getattr(record, k)}" for k in CONTEXT_FIELDS if hasattr(record, k))
        base = f"{record.levelname:<8} {record.name}: {record.getMessage()}"
        return f"{base} [{ctx}]" if ctx else base


def configure_logging(
    level: str = "INFO",
    *,
    console: bool = True,
    json_console: bool = False,
    log_dir: Path | None = None,
) -> logging.Logger:
    root = logging.getLogger("nxtsec")
    root.setLevel(level.upper())
    root.propagate = False
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()

    redactor = RedactionFilter()
    if console:
        ch = logging.StreamHandler()
        ch.setFormatter(JsonFormatter() if json_console else ConsoleFormatter())
        ch.addFilter(redactor)
        root.addHandler(ch)
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_dir / "nxtsec.jsonl", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setFormatter(JsonFormatter())
        fh.addFilter(redactor)
        root.addHandler(fh)
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name if name.startswith("nxtsec") else f"nxtsec.{name}")
