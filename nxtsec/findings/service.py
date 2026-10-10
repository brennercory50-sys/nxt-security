"""Finding triage service.

Wraps the database with a validated state machine (see
``FindingStatus.can_transition``) and an append-only history, so a finding's
life — confirmed, mitigated, accepted, marked a false positive, reopened — is
auditable. Notes and history live in the finding's stored JSON; the dataclass
stays the creation-time shape.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from nxtsec.core.errors import NxtSecError
from nxtsec.core.ids import utcnow
from nxtsec.core.models import FindingStatus, Severity
from nxtsec.database.store import Database


class FindingNotFound(NxtSecError):
    """No finding with the given id."""


class InvalidTransition(NxtSecError):
    """The requested status change is not allowed from the current status."""


def severity_rank(value: str) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return -1


class FindingService:
    def __init__(self, db: Database, operator: str) -> None:
        self.db = db
        self.operator = operator

    def get(self, finding_id: str) -> dict[str, Any]:
        f = self.db.get_finding(finding_id)
        if f is None:
            raise FindingNotFound(f"no such finding: {finding_id}")
        return f

    def resolve(self, ref: str) -> dict[str, Any]:
        """Look up by full id, or by unique id prefix for convenience."""
        if self.db.get_finding(ref) is not None:
            return self.db.get_finding(ref)  # type: ignore[return-value]
        matches = [f for f in self.db.list_findings() if f["id"].startswith(ref)]
        if not matches:
            raise FindingNotFound(f"no such finding: {ref}")
        if len(matches) > 1:
            ids = ", ".join(sorted(m["id"] for m in matches)[:5])
            raise FindingNotFound(f"ambiguous finding prefix {ref!r} matches: {ids}")
        return matches[0]

    def search(
        self,
        *,
        status: str | None = None,
        min_severity: str | None = None,
        open_only: bool = False,
        module: str | None = None,
    ) -> list[dict[str, Any]]:
        findings = self.db.list_findings(status)
        if min_severity is not None:
            floor = Severity(min_severity.upper()).rank
            findings = [f for f in findings if severity_rank(f["severity"]) >= floor]
        if open_only:
            findings = [f for f in findings if FindingStatus(f["status"]).is_open]
        if module is not None:
            findings = [f for f in findings if f.get("detection_module") == module]
        return self.sort(findings)

    @staticmethod
    def sort(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Most severe first, then newest first."""
        return sorted(
            findings,
            key=lambda f: (-severity_rank(f["severity"]), f.get("created_at") or ""),
            reverse=False,
        )

    def set_status(self, ref: str, new_status: str, note: str | None = None) -> dict[str, Any]:
        finding = self.resolve(ref)
        try:
            target = FindingStatus(new_status.upper())
        except ValueError as exc:
            raise InvalidTransition(f"unknown status {new_status!r}") from exc
        current = FindingStatus(finding["status"])
        if target == current:
            raise InvalidTransition(f"finding is already {current.value}")
        if not current.can_transition(target):
            allowed = sorted(s.value for s in FindingStatus if current.can_transition(s))
            raise InvalidTransition(
                f"cannot change {current.value} -> {target.value}; allowed: {allowed or 'none'}"
            )
        finding["status"] = target.value
        self._append_history(finding, f"status {current.value} -> {target.value}", note)
        self.db.update_finding(finding["id"], finding)
        self.db.audit(
            self.operator,
            "finding.status",
            finding["target"],
            {"finding_id": finding["id"], "from": current.value, "to": target.value, "note": note},
        )
        return finding

    def add_note(self, ref: str, note: str) -> dict[str, Any]:
        finding = self.resolve(ref)
        self._append_history(finding, "note", note)
        self.db.update_finding(finding["id"], finding)
        self.db.audit(
            self.operator,
            "finding.note",
            finding["target"],
            {"finding_id": finding["id"], "note": note},
        )
        return finding

    def _append_history(self, finding: dict[str, Any], action: str, note: str | None) -> None:
        entry = {"at": utcnow().isoformat(), "by": self.operator, "action": action}
        if note:
            entry["note"] = note
            finding.setdefault("notes", []).append(
                {"at": entry["at"], "by": self.operator, "text": note}
            )
        finding.setdefault("history", []).append(entry)

    def summary(self, findings: Iterable[dict[str, Any]]) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            if f["severity"] in counts:
                counts[f["severity"]] += 1
        return counts
