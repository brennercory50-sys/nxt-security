"""Write-once evidence store.

Every artifact is hashed (SHA-256) before it is written, written exclusively
(an existing file is never overwritten), made read-only, and recorded in the
database with chain-of-custody metadata. ``verify`` recomputes the hash.

Layout: ``<evidence_dir>/<assessment_id>/<name>``.

Evidence is stored as collected (not redacted) so it stays faithful; anything
*displayed* from it goes through redaction.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from nxtsec.core.errors import NxtSecError
from nxtsec.core.ids import utcnow
from nxtsec.core.models import Evidence
from nxtsec.database.store import Database
from nxtsec.safety.paths import safe_component, safe_join

_READ_ONLY = stat.S_IRUSR | stat.S_IRGRP


class EvidenceError(NxtSecError):
    """Evidence could not be stored or failed verification."""


class EvidenceStore:
    def __init__(self, root: Path, db: Database, operator: str) -> None:
        self.root = root
        self.db = db
        self.operator = operator

    def store_bytes(
        self,
        data: bytes,
        *,
        assessment_id: str,
        name: str,
        type_: str,
        source: str,
        description: str,
        target: str | None = None,
    ) -> Evidence:
        self.root.mkdir(parents=True, exist_ok=True)
        folder = safe_join(self.root, safe_component(assessment_id))
        folder.mkdir(parents=True, exist_ok=True)
        path = safe_join(folder, safe_component(name))
        digest = hashlib.sha256(data).hexdigest()
        try:
            with path.open("xb") as fh:  # exclusive create: never overwrite evidence
                fh.write(data)
        except FileExistsError as exc:
            raise EvidenceError(f"evidence already exists: {path}") from exc
        except OSError as exc:
            raise EvidenceError(f"cannot write evidence {path}: {exc}") from exc
        os.chmod(path, _READ_ONLY)
        ev = Evidence(
            type=type_,
            source=source,
            description=description,
            content_sha256=digest,
            location=str(path),
            target=target,
            assessment_id=assessment_id,
            custody=[
                {
                    "action": "collected",
                    "by": self.operator,
                    "at": utcnow().isoformat(),
                    "sha256": digest,
                    "size": str(len(data)),
                }
            ],
        )
        try:
            self.db.add_evidence(ev)
        except NxtSecError as exc:
            # Never leave an unrecorded artifact behind.
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            path.unlink(missing_ok=True)
            raise EvidenceError(f"cannot record evidence {path.name}: {exc}") from exc
        return ev

    def store_json(self, obj: Any, **kwargs: Any) -> Evidence:
        data = json.dumps(obj, indent=2, sort_keys=True, default=str).encode("utf-8")
        return self.store_bytes(data, **kwargs)

    @staticmethod
    def verify(evidence: dict[str, Any]) -> bool:
        """True if the file still matches the hash recorded at collection time."""
        location = evidence.get("location")
        if not location:
            return False
        h = hashlib.sha256()
        try:
            with open(location, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
        except OSError:
            return False
        return h.hexdigest() == evidence.get("content_sha256")
