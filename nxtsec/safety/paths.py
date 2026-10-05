"""Path validation helpers that stop traversal out of a permitted base directory."""

from __future__ import annotations

from pathlib import Path

from nxtsec.core.errors import PathViolation


def safe_join(base: Path, *parts: str) -> Path:
    """Join ``parts`` under ``base`` and guarantee the result stays inside ``base``.

    Symlinks are resolved, so a link pointing outside ``base`` is rejected.
    """
    root = base.resolve()
    for p in parts:
        if "\x00" in p:
            raise PathViolation("path contains a NUL byte")
    candidate = root.joinpath(*parts).resolve()
    if candidate != root and root not in candidate.parents:
        raise PathViolation(f"path escapes base directory: {Path(*parts)}")
    return candidate


def safe_component(name: str) -> str:
    """Validate a single filename component (no separators, no '..')."""
    if not name or name in (".", "..") or any(c in name for c in "/\\\x00:"):
        raise PathViolation(f"invalid filename component: {name!r}")
    return name
