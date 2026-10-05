"""Database abstraction.

``Database`` is the interface the rest of the platform uses. SQLite (stdlib,
zero setup) is the default backend; a PostgreSQL backend can implement the
same interface later without touching callers. Schema changes are applied
through numbered migrations recorded in ``schema_version``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from nxtsec.core.errors import DatabaseError
from nxtsec.core.ids import new_id, utcnow
from nxtsec.core.models import Assessment, AssessmentStatus, Evidence, Finding, Target

MIGRATIONS: list[str] = [
    # 1: initial schema
    """
    CREATE TABLE assessments (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        target_type TEXT NOT NULL,
        operator TEXT NOT NULL,
        mode TEXT NOT NULL,
        scope_name TEXT NOT NULL,
        modules TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        error TEXT,
        data TEXT NOT NULL
    );
    CREATE TABLE findings (
        id TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL,
        assessment_id TEXT REFERENCES assessments(id),
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        target TEXT NOT NULL,
        module TEXT NOT NULL,
        created_at TEXT NOT NULL,
        data TEXT NOT NULL
    );
    CREATE UNIQUE INDEX ux_findings_fingerprint ON findings(fingerprint);
    CREATE TABLE evidence (
        id TEXT PRIMARY KEY,
        assessment_id TEXT REFERENCES assessments(id),
        sha256 TEXT NOT NULL,
        type TEXT NOT NULL,
        source TEXT NOT NULL,
        created_at TEXT NOT NULL,
        data TEXT NOT NULL
    );
    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        operator TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT NOT NULL
    );
    """,
    # 2: saved targets inventory
    """
    CREATE TABLE targets (
        id TEXT PRIMARY KEY,
        raw TEXT NOT NULL,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        host TEXT,
        label TEXT,
        created_at TEXT NOT NULL
    );
    CREATE UNIQUE INDEX ux_targets_type_value ON targets(type, value);
    """,
    # 3: job control, per-module run records, finding occurrences
    """
    ALTER TABLE assessments ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE assessments ADD COLUMN scope_fingerprint TEXT;
    CREATE INDEX ix_assessments_status ON assessments(status, created_at);
    CREATE TABLE module_runs (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        seq INTEGER NOT NULL,
        module TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        error TEXT,
        observation_count INTEGER NOT NULL DEFAULT 0,
        finding_count INTEGER NOT NULL DEFAULT 0,
        evidence_id TEXT,
        observations TEXT NOT NULL DEFAULT '[]',
        errors TEXT NOT NULL DEFAULT '[]',
        commands TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX ix_module_runs_assessment ON module_runs(assessment_id, seq);
    CREATE TABLE finding_occurrences (
        finding_id TEXT NOT NULL REFERENCES findings(id),
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        seen_at TEXT NOT NULL,
        PRIMARY KEY (finding_id, assessment_id)
    );
    CREATE INDEX ix_evidence_assessment ON evidence(assessment_id);
    """,
]

_ASSESSMENT_COLS = "data,status,started_at,finished_at,error,cancel_requested"


class Database(ABC):
    @abstractmethod
    def migrate(self) -> int: ...

    @abstractmethod
    def schema_version(self) -> int: ...

    @abstractmethod
    def save_assessment(self, a: Assessment) -> None: ...

    @abstractmethod
    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def list_assessments(
        self, limit: int = 50, status: str | None = None
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_queued(self, limit: int = 50) -> list[str]:
        """IDs of queued assessments, oldest first."""

    @abstractmethod
    def claim_assessment(self, assessment_id: str, started_at: str) -> bool:
        """Atomically move queued -> running. False if another worker got it first."""

    @abstractmethod
    def cancel_queued(self, assessment_id: str, finished_at: str) -> bool:
        """Atomically move queued -> cancelled."""

    @abstractmethod
    def request_cancel(self, assessment_id: str) -> bool:
        """Flag a running assessment for cooperative cancellation."""

    @abstractmethod
    def is_cancel_requested(self, assessment_id: str) -> bool: ...

    @abstractmethod
    def add_module_run(self, run: dict[str, Any]) -> None: ...

    @abstractmethod
    def list_module_runs(self, assessment_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def findings_for_assessment(self, assessment_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def list_evidence(self, assessment_id: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]: ...

    @abstractmethod
    def upsert_finding(self, f: Finding) -> tuple[str, bool]:
        """Insert or deduplicate. Returns ``(finding_id, created)``."""

    @abstractmethod
    def list_findings(self, status: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def add_evidence(self, e: Evidence) -> None: ...

    @abstractmethod
    def audit(
        self, operator: str, action: str, target: str | None, detail: dict[str, Any]
    ) -> None: ...

    @abstractmethod
    def add_target(self, target: Target, label: str | None = None) -> tuple[str, bool]:
        """Save a target. Returns ``(target_id, created)``; existing targets are not duplicated."""

    @abstractmethod
    def list_targets(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def remove_target(self, ref: str) -> bool:
        """Remove by ID or exact normalized value. Returns whether anything was removed."""

    @abstractmethod
    def close(self) -> None: ...


class SQLiteDatabase(Database):
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        try:
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
        except sqlite3.Error as exc:
            raise DatabaseError(f"cannot open database {self.path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.RLock()

    def _exec(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        try:
            with self._lock, self._conn:
                return self._conn.execute(sql, params)
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def schema_version(self) -> int:
        with self._lock:
            self._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER)")
            row = self._conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return int(row[0] or 0)

    def migrate(self) -> int:
        current = self.schema_version()
        for i, sql in enumerate(MIGRATIONS[current:], start=current + 1):
            try:
                with self._lock:
                    self._conn.executescript(
                        f"BEGIN;\n{sql}\nINSERT INTO schema_version VALUES ({i});\nCOMMIT;"
                    )
            except sqlite3.Error as exc:
                self._conn.rollback()
                raise DatabaseError(f"migration {i} failed: {exc}") from exc
        return self.schema_version()

    def save_assessment(self, a: Assessment) -> None:
        d = a.to_dict()
        self._exec(
            """INSERT INTO assessments
               (id,target,target_type,operator,mode,scope_name,scope_fingerprint,modules,status,
                created_at,started_at,finished_at,error,data)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET status=excluded.status,
                 started_at=excluded.started_at, finished_at=excluded.finished_at,
                 error=excluded.error, data=excluded.data""",
            (
                a.id,
                a.target.raw,
                a.target.type.value,
                a.operator,
                a.mode.value,
                a.scope_name,
                a.scope_fingerprint,
                json.dumps(a.modules),
                a.status.value,
                d["created_at"],
                d["started_at"],
                d["finished_at"],
                a.error,
                json.dumps(d),
            ),
        )

    @staticmethod
    def _assessment_row(row: sqlite3.Row) -> dict[str, Any]:
        """The JSON blob, overlaid with the authoritative lifecycle columns."""
        d: dict[str, Any] = json.loads(row["data"])
        d.update(
            status=row["status"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            error=row["error"],
            cancel_requested=bool(row["cancel_requested"]),
        )
        return d

    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        row = self._exec(
            f"SELECT {_ASSESSMENT_COLS} FROM assessments WHERE id=?",  # noqa: S608 - constant
            (assessment_id,),
        ).fetchone()
        return self._assessment_row(row) if row else None

    def list_assessments(self, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self._exec(
                f"SELECT {_ASSESSMENT_COLS} FROM assessments WHERE status=? "  # noqa: S608
                "ORDER BY created_at DESC LIMIT ?",
                (status, int(limit)),
            ).fetchall()
        else:
            rows = self._exec(
                f"SELECT {_ASSESSMENT_COLS} FROM assessments "  # noqa: S608
                "ORDER BY created_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [self._assessment_row(r) for r in rows]

    def list_queued(self, limit: int = 50) -> list[str]:
        rows = self._exec(
            "SELECT id FROM assessments WHERE status='queued' ORDER BY created_at LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [str(r["id"]) for r in rows]

    def claim_assessment(self, assessment_id: str, started_at: str) -> bool:
        cur = self._exec(
            "UPDATE assessments SET status='running', started_at=? WHERE id=? AND status='queued'",
            (started_at, assessment_id),
        )
        return cur.rowcount == 1

    def cancel_queued(self, assessment_id: str, finished_at: str) -> bool:
        cur = self._exec(
            "UPDATE assessments SET status='cancelled', finished_at=?, "
            "error='cancelled before start' WHERE id=? AND status='queued'",
            (finished_at, assessment_id),
        )
        return cur.rowcount == 1

    def request_cancel(self, assessment_id: str) -> bool:
        cur = self._exec(
            "UPDATE assessments SET cancel_requested=1 WHERE id=? AND status='running'",
            (assessment_id,),
        )
        return cur.rowcount == 1

    def is_cancel_requested(self, assessment_id: str) -> bool:
        row = self._exec(
            "SELECT cancel_requested FROM assessments WHERE id=?", (assessment_id,)
        ).fetchone()
        return bool(row and row["cancel_requested"])

    def add_module_run(self, run: dict[str, Any]) -> None:
        self._exec(
            """INSERT INTO module_runs
               (id,assessment_id,seq,module,status,started_at,finished_at,error,
                observation_count,finding_count,evidence_id,observations,errors,commands)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run["id"],
                run["assessment_id"],
                run["seq"],
                run["module"],
                run["status"],
                run["started_at"],
                run["finished_at"],
                run.get("error"),
                run.get("observation_count", 0),
                run.get("finding_count", 0),
                run.get("evidence_id"),
                json.dumps(run.get("observations", []), default=str),
                json.dumps(run.get("errors", [])),
                json.dumps(run.get("commands", [])),
            ),
        )

    def list_module_runs(self, assessment_id: str) -> list[dict[str, Any]]:
        rows = self._exec(
            "SELECT * FROM module_runs WHERE assessment_id=? ORDER BY seq", (assessment_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("observations", "errors", "commands"):
                d[k] = json.loads(d[k])
            out.append(d)
        return out

    def _record_occurrence(self, finding_id: str, assessment_id: str | None) -> None:
        if assessment_id:
            self._exec(
                "INSERT OR IGNORE INTO finding_occurrences (finding_id,assessment_id,seen_at) "
                "VALUES (?,?,?)",
                (finding_id, assessment_id, utcnow().isoformat()),
            )

    def upsert_finding(self, f: Finding) -> tuple[str, bool]:
        fp = f.fingerprint
        with self._lock:
            row = self._exec("SELECT id, data FROM findings WHERE fingerprint=?", (fp,)).fetchone()
            if row:
                existing = json.loads(row["data"])
                merged = sorted(set(existing.get("evidence_ids", [])) | set(f.evidence_ids))
                existing["evidence_ids"] = merged
                self._exec(
                    "UPDATE findings SET data=? WHERE id=?", (json.dumps(existing), row["id"])
                )
                self._record_occurrence(str(row["id"]), f.assessment_id)
                return str(row["id"]), False
            d = f.to_dict()
            self._exec(
                """INSERT INTO findings
                   (id,fingerprint,assessment_id,title,severity,status,target,module,created_at,data)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    f.id,
                    fp,
                    f.assessment_id,
                    f.title,
                    f.severity.value,
                    f.status.value,
                    f.target,
                    f.detection_module,
                    d["created_at"],
                    json.dumps(d),
                ),
            )
            self._record_occurrence(f.id, f.assessment_id)
            return f.id, True

    def list_findings(self, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self._exec("SELECT data FROM findings WHERE status=?", (status,)).fetchall()
        else:
            rows = self._exec("SELECT data FROM findings").fetchall()
        return [json.loads(r["data"]) for r in rows]

    def findings_for_assessment(self, assessment_id: str) -> list[dict[str, Any]]:
        rows = self._exec(
            "SELECT f.data FROM findings f JOIN finding_occurrences o ON o.finding_id = f.id "
            "WHERE o.assessment_id=? ORDER BY f.created_at",
            (assessment_id,),
        ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        row = self._exec("SELECT data FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def list_evidence(self, assessment_id: str | None = None) -> list[dict[str, Any]]:
        if assessment_id:
            rows = self._exec(
                "SELECT data FROM evidence WHERE assessment_id=? ORDER BY created_at",
                (assessment_id,),
            ).fetchall()
        else:
            rows = self._exec("SELECT data FROM evidence ORDER BY created_at").fetchall()
        return [json.loads(r["data"]) for r in rows]

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._exec(
            "SELECT id,timestamp,operator,action,target,detail FROM audit_log "
            "ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]

    def add_evidence(self, e: Evidence) -> None:
        d = e.to_dict()
        self._exec(
            "INSERT INTO evidence (id,assessment_id,sha256,type,source,created_at,data) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                e.id,
                e.assessment_id,
                e.content_sha256,
                e.type,
                e.source,
                d["created_at"],
                json.dumps(d),
            ),
        )

    def audit(self, operator: str, action: str, target: str | None, detail: dict[str, Any]) -> None:
        from nxtsec.safety.redaction import redact_obj

        self._exec(
            "INSERT INTO audit_log (timestamp,operator,action,target,detail) VALUES (?,?,?,?,?)",
            (utcnow().isoformat(), operator, action, target, json.dumps(redact_obj(detail))),
        )

    def add_target(self, target: Target, label: str | None = None) -> tuple[str, bool]:
        with self._lock:
            row = self._exec(
                "SELECT id FROM targets WHERE type=? AND value=?",
                (target.type.value, target.value),
            ).fetchone()
            if row:
                return str(row["id"]), False
            tid = new_id("tgt")
            self._exec(
                "INSERT INTO targets (id,raw,type,value,host,label,created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    tid,
                    target.raw,
                    target.type.value,
                    target.value,
                    target.host,
                    label,
                    utcnow().isoformat(),
                ),
            )
            return tid, True

    def list_targets(self) -> list[dict[str, Any]]:
        rows = self._exec(
            "SELECT id,raw,type,value,host,label,created_at FROM targets ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]

    def remove_target(self, ref: str) -> bool:
        cur = self._exec("DELETE FROM targets WHERE id=? OR value=?", (ref, ref))
        return cur.rowcount > 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def open_database(url: str) -> Database:
    """Open a database from a URL. Only ``sqlite:///path`` and ``sqlite://:memory:`` today."""
    if url in ("sqlite://:memory:", "sqlite:///:memory:"):
        db: Database = SQLiteDatabase(":memory:")
    elif url.startswith("sqlite:///"):
        db = SQLiteDatabase(url[len("sqlite:///") :])
    elif url.startswith(("postgres://", "postgresql://")):
        raise DatabaseError("PostgreSQL backend is not implemented yet; use sqlite:///")
    else:
        raise DatabaseError(f"unsupported database URL: {url}")
    db.migrate()
    return db


__all__ = ["AssessmentStatus", "Database", "SQLiteDatabase", "open_database"]
