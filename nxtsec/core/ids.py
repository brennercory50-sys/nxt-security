"""Identifier and timestamp helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def new_id(prefix: str) -> str:
    """Return a sortable-enough, collision-resistant ID such as ``asm_3f2a...``."""
    return f"{prefix}_{uuid.uuid4().hex}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None
