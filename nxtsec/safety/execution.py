"""Safe external command execution.

Rules enforced here, never at call sites:

* argv is always a list; ``shell=True`` is never used;
* the binary is resolved to an absolute path before execution;
* every call has a timeout, and the process is killed if it is exceeded;
* captured output is size-capped;
* the command line and output are redacted before being logged.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # noqa: S404 - this module is the one sanctioned wrapper
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from nxtsec.core.errors import CommandError, CommandTimeout
from nxtsec.safety.redaction import redact

log = logging.getLogger("nxtsec.exec")

DEFAULT_TIMEOUT = 60.0
MAX_TIMEOUT = 6 * 3600.0
DEFAULT_MAX_OUTPUT = 10 * 1024 * 1024


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def resolve_binary(name: str, explicit: str | None = None) -> str | None:
    """Resolve a tool to an absolute path. ``explicit`` (from config) wins over PATH."""
    if explicit:
        p = os.path.abspath(os.path.expanduser(explicit))
        return p if os.path.isfile(p) and os.access(p, os.X_OK) else None
    return shutil.which(name)


def _validate_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, (str, bytes)) or not argv:
        raise CommandError("argv must be a non-empty sequence of strings, not a shell string")
    out: list[str] = []
    for a in argv:
        if not isinstance(a, str):
            raise CommandError(f"argv element is not a string: {a!r}")
        if "\x00" in a:
            raise CommandError("argv element contains a NUL byte")
        out.append(a)
    return out


def _decode(b: bytes, limit: int) -> tuple[str, bool]:
    truncated = len(b) > limit
    return b[:limit].decode("utf-8", errors="replace"), truncated


def run_command(
    argv: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    stdin_data: bytes | None = None,
    binary_path: str | None = None,
) -> CommandResult:
    args = _validate_argv(argv)
    if not (0 < timeout <= MAX_TIMEOUT):
        raise CommandError(f"timeout must be in (0, {MAX_TIMEOUT}]")
    exe = resolve_binary(args[0], binary_path)
    if exe is None:
        raise CommandError(f"executable not found: {args[0]!r}")
    args[0] = exe

    safe_cmdline = redact(" ".join(args))
    log.debug("exec start", extra={"event": "exec.start", "command": safe_cmdline})
    start = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, no shell, resolved binary
            args,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.warning("exec timeout", extra={"event": "exec.timeout", "command": safe_cmdline})
        raise CommandTimeout(f"command timed out after {timeout}s: {safe_cmdline}") from exc
    except OSError as exc:
        raise CommandError(f"failed to execute {safe_cmdline}: {exc}") from exc

    duration = time.monotonic() - start
    stdout, t1 = _decode(proc.stdout, max_output)
    stderr, t2 = _decode(proc.stderr, max_output)
    log.debug(
        "exec end",
        extra={"event": "exec.end", "command": safe_cmdline, "returncode": proc.returncode},
    )
    return CommandResult(tuple(args), proc.returncode, stdout, stderr, duration, t1 or t2)
