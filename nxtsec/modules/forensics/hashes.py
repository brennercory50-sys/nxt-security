"""``forensics.hash``: read-only multi-algorithm hashing of a file or directory tree.

Files are opened read-only, symlinks are never followed, and only regular
files are read (FIFOs and devices are skipped, so the module cannot block).
"""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nxtsec.core.errors import PluginError
from nxtsec.core.models import Target, TargetType
from nxtsec.plugins.base import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    RiskLevel,
)

CHUNK = 1024 * 1024
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def hash_file(path: Path) -> dict[str, Any] | None:
    """Hash one regular file. Returns None if it is not a regular file."""
    fd = os.open(path, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        md5 = hashlib.md5(usedforsecurity=False)  # identification only
        sha1 = hashlib.sha1(usedforsecurity=False)  # identification only
        sha256, sha512 = hashlib.sha256(), hashlib.sha512()
        with os.fdopen(fd, "rb", closefd=False) as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
    finally:
        os.close(fd)
    return {
        "type": "file.hash",
        "path": str(path),
        "size": st.st_size,
        "modified": _iso(st.st_mtime),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


class FileHash(Plugin):
    manifest = PluginManifest(
        name="forensics.hash",
        version="0.1.0",
        description="Read-only MD5/SHA-1/SHA-256/SHA-512 of a file or directory tree",
        category="forensics",
        author="NXT-Security",
        permissions=frozenset({Permission.READ_ONLY, Permission.LOCAL_FILES}),
        risk_level=RiskLevel.PASSIVE,
        target_types=frozenset({TargetType.FILE}),
    )

    def run(self, target: Target | None, ctx: ModuleContext) -> ModuleResult:
        ctx.require(Permission.LOCAL_FILES)
        assert target is not None
        max_files = ctx.option_int("max_files", 10000, 1, 1_000_000)
        root = Path(target.value)
        try:
            st = root.lstat()
        except FileNotFoundError:
            raise PluginError(f"no such file or directory: {root}") from None
        except OSError as exc:
            raise PluginError(f"cannot access {root}: {exc}") from exc

        res = ModuleResult()
        if stat.S_ISLNK(st.st_mode):
            res.observations.append(
                {"type": "file.symlink", "path": str(root), "points_to": os.readlink(root)}
            )
            return res
        if stat.S_ISREG(st.st_mode):
            self._hash_into(root, res)
            return res
        if not stat.S_ISDIR(st.st_mode):
            raise PluginError(f"{root} is not a regular file or directory")

        count = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            ctx.check_cancelled()
            for fname in sorted(filenames):
                if count >= max_files:
                    res.errors.append(f"stopped after max_files={max_files}")
                    return res
                p = Path(dirpath) / fname
                if p.is_symlink():
                    res.observations.append(
                        {"type": "file.symlink", "path": str(p), "points_to": os.readlink(p)}
                    )
                    continue
                self._hash_into(p, res)
                count += 1
        return res

    @staticmethod
    def _hash_into(path: Path, res: ModuleResult) -> None:
        try:
            obs = hash_file(path)
        except OSError as exc:
            res.errors.append(f"{path}: {exc.strerror or exc}")
            return
        if obs is None:
            res.observations.append(
                {"type": "file.skipped", "path": str(path), "reason": "not a regular file"}
            )
        else:
            res.observations.append(obs)
