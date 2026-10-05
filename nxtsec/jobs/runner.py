"""Asynchronous execution of assessments.

* :class:`JobRunner` runs assessments on a thread pool inside this process.
* :func:`spawn_detached` starts a separate ``nxtsec jobs run <id>`` process that
  outlives the CLI invocation (``nxtsec scan run --background``).
* ``nxtsec jobs worker`` (CLI) drains the queue continuously.

Cancellation is cooperative and cross-process: it is a flag in the database
that the engine checks between modules and that modules poll via
``ctx.check_cancelled()``.
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404 - spawns our own interpreter with a fixed argv
import sys
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from nxtsec.core.models import Assessment
from nxtsec.jobs.engine import AssessmentEngine


class JobRunner:
    def __init__(self, engine: AssessmentEngine, max_workers: int = 2) -> None:
        self.engine = engine
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nxtsec-job")
        self._futures: dict[str, Future[Assessment]] = {}
        self._lock = threading.Lock()

    def submit(self, assessment_id: str) -> Future[Assessment]:
        fut = self._pool.submit(self.engine.execute, assessment_id)
        with self._lock:
            self._futures[assessment_id] = fut
        return fut

    def cancel(self, assessment_id: str) -> str:
        return self.engine.cancel(assessment_id)

    def running(self) -> list[str]:
        with self._lock:
            return [aid for aid, f in self._futures.items() if not f.done()]

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)


def worker_argv(assessment_id: str, config_path: Path | None = None) -> list[str]:
    argv = [sys.executable, "-m", "nxtsec"]
    if config_path is not None:
        argv += ["--config", str(config_path)]
    return [*argv, "jobs", "run", assessment_id]


def spawn_detached(assessment_id: str, config_path: Path | None = None) -> int:
    """Start a background worker process for one assessment; return its PID.

    Output is discarded; the worker logs to the normal JSON log file.
    """
    argv = worker_argv(assessment_id, config_path)
    if os.name == "nt":
        flags = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=flags,
        )
    else:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    return proc.pid
