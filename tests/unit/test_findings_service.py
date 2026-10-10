"""Finding triage service: transitions, notes, filtering, history."""

import pytest

from nxtsec.core.models import Confidence, Finding, FindingStatus, Severity
from nxtsec.database.store import SQLiteDatabase
from nxtsec.findings.service import FindingNotFound, FindingService, InvalidTransition


@pytest.fixture
def svc():
    db = SQLiteDatabase(":memory:")
    db.migrate()
    service = FindingService(db, "tester")
    yield service
    db.close()


def _add(svc, title, severity, module="t.mod", status=FindingStatus.OPEN, target="h.test"):
    f = Finding(title, severity, target, module, confidence=Confidence.FIRM, status=status)
    svc.db.upsert_finding(f)
    return f.id


def test_can_transition_rules():
    assert FindingStatus.OPEN.can_transition(FindingStatus.CONFIRMED)
    assert not FindingStatus.OPEN.can_transition(FindingStatus.MITIGATED)
    assert FindingStatus.CONFIRMED.can_transition(FindingStatus.MITIGATED)
    assert FindingStatus.CLOSED.can_transition(FindingStatus.OPEN)  # reopen
    assert not FindingStatus.OPEN.can_transition(FindingStatus.OPEN)
    assert FindingStatus.OPEN.is_open and FindingStatus.CONFIRMED.is_open
    assert not FindingStatus.CLOSED.is_open


def test_set_status_valid_and_history(svc):
    fid = _add(svc, "X", Severity.HIGH)
    f = svc.set_status(fid, "confirmed", note="reproduced")
    assert f["status"] == "CONFIRMED"
    assert f["history"][0]["action"] == "status OPEN -> CONFIRMED"
    assert f["notes"][0]["text"] == "reproduced" and f["notes"][0]["by"] == "tester"
    # persisted
    assert svc.db.get_finding(fid)["status"] == "CONFIRMED"
    # audited
    actions = [a["action"] for a in svc.db.list_audit()]
    assert "finding.status" in actions


def test_invalid_transition(svc):
    fid = _add(svc, "X", Severity.LOW)
    with pytest.raises(InvalidTransition, match="cannot change OPEN -> MITIGATED"):
        svc.set_status(fid, "mitigated")
    with pytest.raises(InvalidTransition, match="already OPEN"):
        svc.set_status(fid, "open")
    with pytest.raises(InvalidTransition, match="unknown status"):
        svc.set_status(fid, "bogus")


def test_reopen_cycle(svc):
    fid = _add(svc, "X", Severity.MEDIUM)
    svc.set_status(fid, "false_positive")
    f = svc.set_status(fid, "open", note="actually real")
    assert f["status"] == "OPEN" and len(f["history"]) == 2


def test_resolve_by_prefix(svc):
    fid = _add(svc, "X", Severity.HIGH)
    assert svc.resolve(fid[:12])["id"] == fid
    with pytest.raises(FindingNotFound, match="no such"):
        svc.resolve("fnd_doesnotexist")


def test_resolve_ambiguous_prefix(svc, monkeypatch):
    _add(svc, "A", Severity.LOW)
    _add(svc, "B", Severity.LOW)
    with pytest.raises(FindingNotFound, match="ambiguous"):
        svc.resolve("fnd_")


def test_add_note(svc):
    fid = _add(svc, "X", Severity.INFO)
    f = svc.add_note(fid, "needs owner review")
    assert f["notes"][-1]["text"] == "needs owner review"
    assert f["history"][-1]["action"] == "note"


def test_search_filters_and_sort(svc):
    _add(svc, "crit", Severity.CRITICAL)
    _add(svc, "low", Severity.LOW, module="other")
    cid = _add(svc, "high-confirmed", Severity.HIGH)
    svc.set_status(cid, "confirmed")
    svc.set_status(_add(svc, "closed-med", Severity.MEDIUM), "closed")

    ordered = svc.search()
    assert [f["severity"] for f in ordered][:2] == ["CRITICAL", "HIGH"]
    assert {f["severity"] for f in svc.search(min_severity="HIGH")} == {"CRITICAL", "HIGH"}
    assert all(f["detection_module"] == "other" for f in svc.search(module="other"))
    open_ones = svc.search(open_only=True)
    assert all(f["status"] in ("OPEN", "CONFIRMED") for f in open_ones)
    assert "closed-med" not in {f["title"] for f in open_ones}
    assert {f["status"] for f in svc.search(status="CLOSED")} == {"CLOSED"}


def test_summary(svc):
    _add(svc, "a", Severity.HIGH)
    _add(svc, "b", Severity.HIGH)
    _add(svc, "c", Severity.LOW)
    counts = svc.summary(svc.search())
    assert counts["HIGH"] == 2 and counts["LOW"] == 1 and counts["CRITICAL"] == 0
