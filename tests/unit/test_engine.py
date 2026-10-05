"""Phase 7: assessment lifecycle, isolation, cancellation, re-authorization, evidence."""

import json
import os
import stat
import threading
from pathlib import Path

import pytest

from nxtsec.core.errors import JobError, PluginError, ScopeViolation, TargetError
from nxtsec.core.models import (
    AssessmentStatus,
    Confidence,
    Finding,
    Mode,
    Severity,
    TargetType,
)
from nxtsec.database.store import SQLiteDatabase
from nxtsec.events import EventBus
from nxtsec.evidence import EvidenceStore
from nxtsec.jobs import AssessmentEngine, JobRunner, assessment_from_dict
from nxtsec.jobs.runner import worker_argv
from nxtsec.plugins import (
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    PluginRegistry,
    RiskLevel,
)
from nxtsec.plugins.policy import Policy
from nxtsec.safety.scope import Scope

SCOPE = Scope(["192.168.1.0/24", "localhost"], ["192.168.1.1"], name="t", attestation="test")


def plugin(name, behavior, *, perms=None, risk=RiskLevel.LOW, types=None, validate=None):
    class P(Plugin):
        manifest = PluginManifest(
            name=name,
            version="1.0.0",
            description="t",
            category="test",
            permissions=perms or frozenset({Permission.NETWORK_ACCESS}),
            risk_level=risk,
            target_types=types or frozenset({TargetType.IPV4}),
        )

        @classmethod
        def validate_options(cls, options):
            if validate:
                validate(options)

        def run(self, target, ctx):
            return behavior(target, ctx)

    return P


def ok(target, ctx):
    return ModuleResult(
        observations=[{"type": "t", "host": target.value, "token": "api_key=supersecret123"}],
        findings=[
            Finding("Thing found", Severity.LOW, target.value, "", confidence=Confidence.FIRM)
        ],
    )


def boom(target, ctx):
    raise RuntimeError("module exploded")


class Env:
    def __init__(self, tmp_path, scope=SCOPE, plugins=()):
        self.db = SQLiteDatabase(":memory:")
        self.db.migrate()
        self.reg = PluginRegistry()
        for p in plugins:
            self.reg.register(p)
        self.scope = scope
        self.bus = EventBus()
        self.events = []
        self.bus.subscribe("*", lambda e: self.events.append(e.name))
        self.evidence = EvidenceStore(tmp_path / "evidence", self.db, "tester")
        self.engine = AssessmentEngine(
            db=self.db,
            registry=self.reg,
            scope_loader=lambda: self.scope,
            policy=Policy(),
            bus=self.bus,
            evidence=self.evidence,
            operator="tester",
        )

    def audit_actions(self):
        return [a["action"] for a in self.db.list_audit(500)]


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path, plugins=(plugin("t.ok", ok), plugin("t.boom", boom)))
    yield e
    e.db.close()


# -- planning -----------------------------------------------------------------
def test_plan_persists_queued(env):
    a = env.engine.plan("192.168.1.5", ["t.ok", "t.ok"], options={"ports": "1"})
    d = env.db.get_assessment(a.id)
    assert d["status"] == "queued" and d["modules"] == ["t.ok"]  # deduplicated
    assert d["scope_fingerprint"] == SCOPE.fingerprint and d["operator"] == "tester"
    assert "assessment.create" in env.audit_actions()
    assert "assessment.queued" in env.events


def test_plan_out_of_scope_is_refused_and_audited(env):
    with pytest.raises(ScopeViolation):
        env.engine.plan("8.8.8.8", ["t.ok"])
    assert env.db.list_assessments() == []
    refused = [a for a in env.db.list_audit() if a["action"] == "assessment.refused"]
    assert refused and "out of scope" in refused[0]["detail"]["reason"]


@pytest.mark.parametrize(
    ("target", "modules", "options", "exc"),
    [
        ("192.168.1.5", [], {}, JobError),
        ("192.168.1.5", ["  "], {}, JobError),
        ("192.168.1.5", ["nope"], {}, PluginError),
        ("not a target!", ["t.ok"], {}, TargetError),
        ("192.168.1.5", ["t.ok"], {"Bad Key": "x"}, JobError),
        ("192.168.1.5", ["t.ok"], {"k": "x" * 5000}, JobError),
        ("192.168.1.5", ["t.ok"], {f"k{i}": "v" for i in range(40)}, JobError),
        ("lab:dvwa", ["t.ok"], {}, PluginError),
    ],
)
def test_plan_rejections(env, target, modules, options, exc):
    with pytest.raises(exc):
        env.engine.plan(target, modules, options=options)


def test_plan_runs_module_option_validation(tmp_path):
    def reject(opts):
        if "ports" in opts:
            raise PluginError("bad ports")

    e = Env(tmp_path, plugins=(plugin("t.v", ok, validate=reject),))
    with pytest.raises(PluginError, match="bad ports"):
        e.engine.plan("192.168.1.5", ["t.v"], options={"ports": "x"})


# -- execution ----------------------------------------------------------------
def test_execute_happy_path(env):
    a = env.engine.plan("192.168.1.5", ["t.ok"])
    done = env.engine.execute(a.id)
    assert done.status == AssessmentStatus.COMPLETED and done.error is None
    d = env.db.get_assessment(a.id)
    assert d["status"] == "completed" and d["started_at"] and d["finished_at"]

    [run] = env.db.list_module_runs(a.id)
    assert run["status"] == "completed" and run["observation_count"] == 1
    assert "supersecret123" not in json.dumps(run)  # redacted in the DB

    [ev] = env.db.list_evidence(a.id)
    assert ev["id"] == run["evidence_id"] and EvidenceStore.verify(ev)
    raw = Path(ev["location"]).read_text(encoding="utf-8")
    assert "supersecret123" in raw  # evidence is kept faithful
    assert not os.stat(ev["location"]).st_mode & stat.S_IWUSR  # read-only
    assert ev["custody"][0]["by"] == "tester"

    [f] = env.db.findings_for_assessment(a.id)
    assert f["detection_module"] == "t.ok" and ev["id"] in f["evidence_ids"]

    actions = env.audit_actions()
    assert {"assessment.create", "module.run", "assessment.completed"} <= set(actions)
    assert env.events.index("module.started") < env.events.index("module.finished")


def test_execute_only_once(env):
    a = env.engine.plan("192.168.1.5", ["t.ok"])
    env.engine.execute(a.id)
    with pytest.raises(JobError, match="completed, not queued"):
        env.engine.execute(a.id)
    with pytest.raises(JobError, match="no such"):
        env.engine.execute("asm_missing")


def test_module_failure_is_isolated(env):
    a = env.engine.plan("192.168.1.5", ["t.boom", "t.ok"])
    done = env.engine.execute(a.id)
    assert done.status == AssessmentStatus.COMPLETED
    assert "t.boom: RuntimeError: module exploded" in done.error
    runs = env.db.list_module_runs(a.id)
    assert [r["status"] for r in runs] == ["failed", "completed"]
    assert len(env.db.list_evidence(a.id)) == 2  # failures leave evidence too


def test_all_modules_failing_fails_assessment(env):
    a = env.engine.plan("192.168.1.5", ["t.boom"])
    assert env.engine.execute(a.id).status == AssessmentStatus.FAILED


def test_module_returning_garbage(tmp_path):
    e = Env(tmp_path, plugins=(plugin("t.bad", lambda t, c: {"not": "a result"}),))
    a = e.engine.plan("192.168.1.5", ["t.bad"])
    done = e.engine.execute(a.id)
    assert done.status == AssessmentStatus.FAILED and "not ModuleResult" in done.error


def test_module_evidence_sink(tmp_path):
    def saves(target, ctx):
        ev = ctx.save_evidence(b"raw bytes", "capture.bin", "raw", "a capture")
        return ModuleResult(
            findings=[Finding("x", Severity.INFO, target.value, "", evidence_ids=[ev.id])]
        )

    e = Env(tmp_path, plugins=(plugin("t.sink", saves),))
    a = e.engine.plan("192.168.1.5", ["t.sink"])
    e.engine.execute(a.id)
    evs = e.db.list_evidence(a.id)
    assert len(evs) == 2 and all(EvidenceStore.verify(x) for x in evs)
    [f] = e.db.findings_for_assessment(a.id)
    assert len(f["evidence_ids"]) == 2


def test_evidence_never_overwritten(env):
    from nxtsec.evidence.store import EvidenceError

    aid = env.engine.plan("192.168.1.5", ["t.ok"]).id
    kw = dict(assessment_id=aid, name="f.txt", type_="t", source="s", description="d")
    first = env.evidence.store_bytes(b"a", **kw)
    with pytest.raises(EvidenceError, match="already exists"):
        env.evidence.store_bytes(b"b", **kw)
    assert Path(first.location).read_bytes() == b"a"


def test_unrecordable_evidence_leaves_no_file(env):
    from nxtsec.evidence.store import EvidenceError

    with pytest.raises(EvidenceError, match="cannot record"):
        env.evidence.store_bytes(
            b"x", assessment_id="asm_ghost", name="f.txt", type_="t", source="s", description="d"
        )
    assert not (env.evidence.root / "asm_ghost" / "f.txt").exists()


@pytest.mark.parametrize("name", ["../escape.txt", "a/b", "..", ""])
def test_evidence_names_cannot_escape(env, name):
    from nxtsec.core.errors import PathViolation

    aid = env.engine.plan("192.168.1.5", ["t.ok"]).id
    with pytest.raises(PathViolation):
        env.evidence.store_bytes(
            b"x", assessment_id=aid, name=name, type_="t", source="s", description="d"
        )


def test_evidence_tamper_detected(env):
    a = env.engine.plan("192.168.1.5", ["t.ok"])
    env.engine.execute(a.id)
    [ev] = env.db.list_evidence(a.id)
    os.chmod(ev["location"], stat.S_IRUSR | stat.S_IWUSR)
    with open(ev["location"], "a", encoding="utf-8") as fh:
        fh.write("tampered")
    assert not EvidenceStore.verify(ev)


# -- re-authorization ------------------------------------------------------------
def test_scope_revoked_before_run(env):
    a = env.engine.plan("192.168.1.5", ["t.ok"])
    env.scope = Scope(["10.0.0.0/8"], attestation="x")
    done = env.engine.execute(a.id)
    assert done.status == AssessmentStatus.FAILED
    assert "authorization failed at run time" in done.error
    assert env.db.list_module_runs(a.id) == []


def test_scope_changed_but_still_authorized(env):
    a = env.engine.plan("192.168.1.5", ["t.ok"])
    env.scope = Scope(["192.168.0.0/16"], attestation="new")
    assert env.engine.execute(a.id).status == AssessmentStatus.COMPLETED
    assert "assessment.scope_changed" in env.audit_actions()


# -- cancellation ----------------------------------------------------------------
def test_cancel_queued(env):
    a = env.engine.plan("192.168.1.5", ["t.ok"])
    assert env.engine.cancel(a.id) == "cancelled"
    assert env.db.get_assessment(a.id)["status"] == "cancelled"
    with pytest.raises(JobError):
        env.engine.execute(a.id)
    with pytest.raises(JobError, match="already cancelled"):
        env.engine.cancel(a.id)
    with pytest.raises(JobError, match="no such"):
        env.engine.cancel("asm_missing")


def test_cancel_inside_module(tmp_path):
    holder = {}

    def cooperative(target, ctx):
        holder["engine"].cancel(ctx.assessment_id)  # as if from another process
        ctx.check_cancelled()
        return ModuleResult()

    ran = []
    e = Env(
        tmp_path,
        plugins=(
            plugin("t.coop", cooperative),
            plugin("t.after", lambda t, c: ran.append(1) or ModuleResult()),
        ),
    )
    holder["engine"] = e.engine
    a = e.engine.plan("192.168.1.5", ["t.coop", "t.after"])
    done = e.engine.execute(a.id)
    assert done.status == AssessmentStatus.CANCELLED and ran == []
    assert e.db.list_module_runs(a.id)[0]["status"] == "cancelled"


def test_cancel_between_modules(tmp_path):
    holder = {}

    def first(target, ctx):
        holder["engine"].cancel(ctx.assessment_id)
        return ModuleResult(observations=[{"type": "x"}])  # finishes its work

    e = Env(tmp_path, plugins=(plugin("t.first", first), plugin("t.ok", ok)))
    holder["engine"] = e.engine
    a = e.engine.plan("192.168.1.5", ["t.first", "t.ok"])
    done = e.engine.execute(a.id)
    assert done.status == AssessmentStatus.CANCELLED
    assert [r["module"] for r in e.db.list_module_runs(a.id)] == ["t.first"]


# -- findings ----------------------------------------------------------------------
def test_findings_deduplicated_across_assessments(env):
    a1 = env.engine.plan("192.168.1.5", ["t.ok"])
    env.engine.execute(a1.id)
    a2 = env.engine.plan("192.168.1.5", ["t.ok"])
    env.engine.execute(a2.id)
    assert len(env.db.list_findings()) == 1
    f1 = env.db.findings_for_assessment(a1.id)
    f2 = env.db.findings_for_assessment(a2.id)
    assert f1[0]["id"] == f2[0]["id"]
    # one shared record, evidence accumulated from both assessments
    ev_ids = {e["id"] for a in (a1, a2) for e in env.db.list_evidence(a.id)}
    assert set(f2[0]["evidence_ids"]) == ev_ids and len(ev_ids) == 2
    assert "finding.seen_again" in env.events


# -- concurrency -------------------------------------------------------------------
def test_claim_is_exclusive(env):
    a = env.engine.plan("192.168.1.5", ["t.ok"])
    outcomes, barrier = [], threading.Barrier(4)

    def go():
        barrier.wait()
        try:
            env.engine.execute(a.id)
            outcomes.append("ran")
        except JobError:
            outcomes.append("skipped")

    threads = [threading.Thread(target=go) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["ran", "skipped", "skipped", "skipped"]
    assert len(env.db.list_module_runs(a.id)) == 1


def test_job_runner(env):
    ids = [env.engine.plan(f"192.168.1.{i}", ["t.ok"]).id for i in range(10, 14)]
    runner = JobRunner(env.engine, max_workers=3)
    futures = [runner.submit(i) for i in ids]
    results = [f.result(timeout=30) for f in futures]
    runner.shutdown()
    assert all(r.status == AssessmentStatus.COMPLETED for r in results)
    assert runner.running() == []


def test_run_queued(env):
    ids = [env.engine.plan(f"192.168.1.{i}", ["t.ok"]).id for i in range(20, 23)]
    env.engine.cancel(ids[1])
    done = env.engine.run_queued()
    assert [a.id for a in done] == [ids[0], ids[2]]
    assert env.engine.run_queued() == []
    more = [env.engine.plan(f"192.168.1.{i}", ["t.ok"]).id for i in range(30, 33)]
    assert len(env.engine.run_queued(limit=2)) == 2
    assert env.db.list_queued() == [more[2]]


# -- robustness --------------------------------------------------------------------
def test_internal_crash_marks_failed(env, monkeypatch):
    a = env.engine.plan("192.168.1.5", ["t.ok"])

    def broken(run):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(env.db, "add_module_run", broken)
    done = env.engine.execute(a.id)
    assert done.status == AssessmentStatus.FAILED and "disk on fire" in done.error
    assert env.db.get_assessment(a.id)["status"] == "failed"


def test_illegal_transition():
    from nxtsec.core.models import Assessment
    from nxtsec.targets import parse_target

    a = Assessment(parse_target("10.0.0.1"), "op", ["m"])
    with pytest.raises(ValueError):
        a.transition(AssessmentStatus.COMPLETED)
    a.transition(AssessmentStatus.RUNNING)
    a.transition(AssessmentStatus.FAILED)
    with pytest.raises(ValueError):
        a.transition(AssessmentStatus.RUNNING)


def test_assessment_roundtrip(env):
    a = env.engine.plan("192.168.1.5", ["t.ok"], options={"timeout": "3"})
    b = assessment_from_dict(env.db.get_assessment(a.id))
    assert (b.id, b.target, b.modules, b.options, b.mode) == (
        a.id,
        a.target,
        a.modules,
        a.options,
        Mode.REAL,
    )


def test_worker_argv():
    argv = worker_argv("asm_1")
    assert argv[1:] == ["-m", "nxtsec", "jobs", "run", "asm_1"]
    from pathlib import Path

    assert "--config" in worker_argv("asm_1", Path("c.yaml"))
