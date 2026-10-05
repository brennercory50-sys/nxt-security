import pytest

from nxtsec.core.errors import DatabaseError
from nxtsec.core.models import Assessment, AssessmentStatus, Evidence, Finding, Severity
from nxtsec.database import open_database
from nxtsec.database.store import MIGRATIONS
from nxtsec.targets import parse_target


@pytest.fixture
def db(tmp_path):
    d = open_database(f"sqlite:///{tmp_path / 'db' / 't.db'}")
    yield d
    d.close()


def test_migrations_idempotent(db):
    assert db.schema_version() == len(MIGRATIONS)
    assert db.migrate() == len(MIGRATIONS)


def test_assessment_roundtrip(db):
    a = Assessment(parse_target("192.168.1.5"), "op", ["demo"])
    db.save_assessment(a)
    a.status = AssessmentStatus.COMPLETED
    db.save_assessment(a)
    got = db.get_assessment(a.id)
    assert got["status"] == "completed" and got["target"]["host"] == "192.168.1.5"
    assert len(db.list_assessments()) == 1
    assert db.get_assessment("nope") is None


def test_finding_dedup(db):
    f1 = Finding(
        "Missing HSTS", Severity.LOW, "https://x.local", "web.headers", evidence_ids=["e1"]
    )
    f2 = Finding(
        "missing hsts", Severity.LOW, "https://X.local", "web.headers", evidence_ids=["e2"]
    )
    id1, c1 = db.upsert_finding(f1)
    id2, c2 = db.upsert_finding(f2)
    assert c1 and not c2 and id1 == id2
    [only] = db.list_findings()
    assert only["evidence_ids"] == ["e1", "e2"]
    assert db.list_findings("OPEN") and not db.list_findings("CLOSED")


def test_evidence_and_audit_redacted(db):
    db.add_evidence(Evidence("http_response", "web.headers", "resp", Evidence.hash_bytes(b"body")))
    db.audit("op", "scan", "x", {"cmd": "curl -H 'Authorization: Bearer abcdefghijklmnopqrs'"})
    row = db._exec("SELECT detail FROM audit_log").fetchone()  # noqa: SLF001
    assert "abcdefghijklmnopqrs" not in row["detail"]


@pytest.mark.parametrize("url", ["mysql://x", "postgresql://u@h/db", "nonsense"])
def test_unsupported_urls(url):
    with pytest.raises(DatabaseError):
        open_database(url)
