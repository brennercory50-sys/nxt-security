"""Assessment engine.

Lifecycle::

    plan()     -> authorize every module (scope, permissions, risk, mode), persist QUEUED
    execute()  -> atomically claim QUEUED -> RUNNING, re-authorize against the *current*
                  scope, run modules in order, store evidence/findings/module runs,
                  finish as COMPLETED, FAILED or CANCELLED
    cancel()   -> QUEUED -> CANCELLED immediately; RUNNING -> cooperative cancel flag

A module that raises never takes the assessment down with it: its failure is
recorded and the next module runs. The assessment FAILS only if every module
failed (or authorization was revoked before it started).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from nxtsec.core.errors import Cancelled, JobError, NxtSecError, PluginError
from nxtsec.core.ids import new_id, utcnow
from nxtsec.core.models import Assessment, AssessmentStatus, Evidence, Mode, Target
from nxtsec.database.store import Database
from nxtsec.events.bus import EventBus
from nxtsec.evidence.store import EvidenceStore
from nxtsec.logging.setup import MODULE_KEY
from nxtsec.plugins.base import ModuleContext, ModuleResult, Permission, Plugin
from nxtsec.plugins.policy import Policy
from nxtsec.plugins.registry import PluginRegistry
from nxtsec.safety.redaction import redact, redact_obj
from nxtsec.safety.scope import Scope
from nxtsec.targets.parser import parse_target

log = logging.getLogger("nxtsec.jobs")

_OPTION_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_MAX_OPTIONS = 32
_MAX_OPTION_LEN = 1024


def validate_options(options: Mapping[str, str]) -> dict[str, str]:
    if len(options) > _MAX_OPTIONS:
        raise JobError(f"too many options (max {_MAX_OPTIONS})")
    out: dict[str, str] = {}
    for k, v in options.items():
        if not isinstance(k, str) or not _OPTION_KEY.match(k):
            raise JobError(f"invalid option name {k!r}")
        if not isinstance(v, str) or len(v) > _MAX_OPTION_LEN or "\x00" in v:
            raise JobError(f"invalid value for option {k!r}")
        out[k] = v
    return out


def _parse_dt(value: Any) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def assessment_from_dict(d: Mapping[str, Any]) -> Assessment:
    """Rebuild an :class:`Assessment` from its stored representation."""
    t = d["target"]
    target = parse_target(t["raw"])
    return Assessment(
        target=target,
        operator=d["operator"],
        modules=list(d["modules"]),
        mode=Mode(d["mode"]),
        scope_name=d["scope_name"],
        scope_fingerprint=d.get("scope_fingerprint"),
        options=dict(d.get("options") or {}),
        status=AssessmentStatus(d["status"]),
        id=d["id"],
        created_at=_parse_dt(d["created_at"]) or utcnow(),
        started_at=_parse_dt(d.get("started_at")),
        finished_at=_parse_dt(d.get("finished_at")),
        error=d.get("error"),
    )


class AssessmentEngine:
    def __init__(
        self,
        *,
        db: Database,
        registry: PluginRegistry,
        scope_loader: Callable[[], Scope],
        policy: Policy,
        bus: EventBus,
        evidence: EvidenceStore,
        operator: str,
    ) -> None:
        self.db = db
        self.registry = registry
        self.scope_loader = scope_loader
        self.policy = policy
        self.bus = bus
        self.evidence = evidence
        self.operator = operator

    # -- planning ----------------------------------------------------------
    def plan(
        self,
        raw_target: str,
        modules: Sequence[str],
        *,
        mode: Mode = Mode.REAL,
        options: Mapping[str, str] | None = None,
    ) -> Assessment:
        names = list(dict.fromkeys(m.strip() for m in modules if m and m.strip()))
        if not names:
            raise JobError("at least one module is required")
        opts = validate_options(options or {})
        target = parse_target(raw_target)  # TargetError propagates
        scope = self.scope_loader()
        try:
            for name in names:
                cls = self.registry.get(name)
                self.policy.authorize(cls.manifest, target, mode, scope)
                cls.validate_options(opts)
        except NxtSecError as exc:
            self.db.audit(
                self.operator,
                "assessment.refused",
                target.raw,
                {"modules": names, "mode": mode.value, "scope": scope.name, "reason": str(exc)},
            )
            raise

        a = Assessment(
            target=target,
            operator=self.operator,
            modules=names,
            mode=mode,
            scope_name=scope.name,
            scope_fingerprint=scope.fingerprint,
            options=opts,
        )
        self.db.save_assessment(a)
        self.db.audit(
            self.operator,
            "assessment.create",
            target.raw,
            {
                "assessment_id": a.id,
                "modules": names,
                "mode": mode.value,
                "scope": scope.name,
                "scope_fingerprint": scope.fingerprint,
                "options": opts,
            },
        )
        self.bus.publish("assessment.queued", assessment_id=a.id, target=target.raw)
        return a

    # -- loading -----------------------------------------------------------
    def load(self, assessment_id: str) -> Assessment:
        d = self.db.get_assessment(assessment_id)
        if d is None:
            raise JobError(f"no such assessment: {assessment_id}")
        return assessment_from_dict(d)

    # -- execution ---------------------------------------------------------
    def execute(self, assessment_id: str) -> Assessment:
        started = utcnow()
        if not self.db.claim_assessment(assessment_id, started.isoformat()):
            d = self.db.get_assessment(assessment_id)
            if d is None:
                raise JobError(f"no such assessment: {assessment_id}")
            raise JobError(f"assessment {assessment_id} is {d['status']}, not queued")

        a = self.load(assessment_id)
        alog = logging.LoggerAdapter(
            log, {"assessment_id": a.id, "target": a.target.raw, "event": "assessment"}
        )
        alog.info("assessment started")
        self.bus.publish("assessment.started", assessment_id=a.id, target=a.target.raw)
        try:
            return self._execute_claimed(a)
        except Exception as exc:  # noqa: BLE001 - a job must never be left RUNNING
            alog.exception("assessment crashed")
            return self._finish(a, AssessmentStatus.FAILED, f"internal error: {exc}")

    def _execute_claimed(self, a: Assessment) -> Assessment:
        # Re-authorize: the scope may have changed or expired since planning.
        try:
            scope = self.scope_loader()
            planned: list[tuple[str, type[Plugin], frozenset[Permission]]] = []
            for name in a.modules:
                cls = self.registry.get(name)
                granted = self.policy.authorize(cls.manifest, a.target, a.mode, scope)
                planned.append((name, cls, granted))
        except NxtSecError as exc:
            return self._finish(
                a, AssessmentStatus.FAILED, f"authorization failed at run time: {exc}"
            )
        if scope.fingerprint != a.scope_fingerprint:
            log.warning(
                "scope changed since planning; re-authorized against current scope",
                extra={"assessment_id": a.id, "event": "scope.changed"},
            )
            self.db.audit(
                self.operator,
                "assessment.scope_changed",
                a.target.raw,
                {
                    "assessment_id": a.id,
                    "planned": a.scope_fingerprint,
                    "current": scope.fingerprint,
                },
            )

        failures: list[str] = []
        successes = 0
        for seq, (name, cls, granted) in enumerate(planned):
            if self.db.is_cancel_requested(a.id):
                return self._finish(a, AssessmentStatus.CANCELLED, "cancelled by operator")
            status, error = self._run_module(a, seq, name, cls, granted, scope)
            if status == "cancelled":
                return self._finish(a, AssessmentStatus.CANCELLED, "cancelled by operator")
            if status == "completed":
                successes += 1
            else:
                failures.append(f"{name}: {error}")

        if failures and successes == 0:
            return self._finish(a, AssessmentStatus.FAILED, "; ".join(failures))
        return self._finish(a, AssessmentStatus.COMPLETED, "; ".join(failures) or None)

    def _run_module(
        self,
        a: Assessment,
        seq: int,
        name: str,
        cls: type[Plugin],
        granted: frozenset[Permission],
        scope: Scope,
    ) -> tuple[str, str | None]:
        mlog = logging.LoggerAdapter(
            log,
            {"assessment_id": a.id, MODULE_KEY: name, "target": a.target.raw, "event": "module"},
        )
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        counter = {"n": 0}

        def sink(data: bytes, ev_name: str, type_: str, description: str) -> Evidence:
            counter["n"] += 1
            return self.evidence.store_bytes(
                data,
                assessment_id=a.id,
                name=f"{seq:02d}-{safe_name}-{counter['n']:03d}-{ev_name}",
                type_=type_,
                source=name,
                description=description,
                target=a.target.raw,
            )

        ctx = ModuleContext(
            assessment_id=a.id,
            mode=a.mode,
            scope=scope,
            granted=granted,
            logger=mlog,
            bus=self.bus,
            options=a.options,
            module_name=name,
            cancel_check=lambda: self.db.is_cancel_requested(a.id),
            evidence_sink=sink,
        )
        started = utcnow()
        self.bus.publish("module.started", assessment_id=a.id, module=name)
        mlog.info("module started")
        status, error = "completed", None
        result = ModuleResult()
        try:
            out = cls().run(a.target, ctx)
            if not isinstance(out, ModuleResult):
                raise PluginError(f"{name} returned {type(out).__name__}, not ModuleResult")
            result = out
        except Cancelled:
            status, error = "cancelled", "cancelled by operator"
        except NxtSecError as exc:
            status, error = "failed", str(exc)
        except Exception as exc:  # noqa: BLE001 - isolate module crashes
            mlog.exception("module crashed")
            status, error = "failed", f"{type(exc).__name__}: {exc}"
        finished = utcnow()
        error = redact(error) if error else None

        record = self.evidence.store_json(
            {
                "assessment_id": a.id,
                "module": name,
                "target": a.target.to_dict(),
                "operator": self.operator,
                "mode": a.mode.value,
                "scope": a.scope_name,
                "started_at": started.isoformat(),
                "finished_at": finished.isoformat(),
                "status": status,
                "error": error,
                "observations": result.observations,
                "errors": result.errors,
                "commands": result.commands,
            },
            assessment_id=a.id,
            name=f"{seq:02d}-{safe_name}.json",
            type_="module_result",
            source=name,
            description=f"Raw result of {name}",
            target=a.target.raw,
        )

        for ev in result.evidence:
            if self.db.get_evidence(ev.id) is None:
                ev.assessment_id = a.id
                ev.target = ev.target or a.target.raw
                self.db.add_evidence(ev)

        finding_count = 0
        for f in result.findings:
            f.assessment_id = a.id
            f.detection_module = f.detection_module or name
            f.evidence_ids = [*f.evidence_ids, record.id]
            fid, created = self.db.upsert_finding(f)
            finding_count += 1
            self.bus.publish(
                "finding.created" if created else "finding.seen_again",
                assessment_id=a.id,
                finding_id=fid,
            )

        self.db.add_module_run(
            {
                "id": new_id("run"),
                "assessment_id": a.id,
                "seq": seq,
                "module": name,
                "status": status,
                "started_at": started.isoformat(),
                "finished_at": finished.isoformat(),
                "error": error,
                "observation_count": len(result.observations),
                "finding_count": finding_count,
                "evidence_id": record.id,
                "observations": redact_obj(result.observations),
                "errors": redact_obj(result.errors),
                "commands": redact_obj(result.commands),
            }
        )
        self.db.audit(
            self.operator,
            "module.run",
            a.target.raw,
            {
                "assessment_id": a.id,
                "module": name,
                "status": status,
                "error": error,
                "observations": len(result.observations),
                "findings": finding_count,
                "evidence_id": record.id,
                "commands": result.commands,
            },
        )
        mlog.info(f"module {status}", extra={"event": f"module.{status}"})
        self.bus.publish(
            "module.finished",
            assessment_id=a.id,
            module=name,
            status=status,
            error=error,
            observations=len(result.observations),
            findings=finding_count,
        )
        return status, error

    def _finish(self, a: Assessment, status: AssessmentStatus, error: str | None) -> Assessment:
        a.transition(status)
        a.finished_at = utcnow()
        a.error = error
        self.db.save_assessment(a)
        self.db.audit(
            self.operator,
            f"assessment.{status.value}",
            a.target.raw,
            {"assessment_id": a.id, "error": error},
        )
        log.info(
            f"assessment {status.value}",
            extra={"assessment_id": a.id, "event": f"assessment.{status.value}"},
        )
        self.bus.publish(f"assessment.{status.value}", assessment_id=a.id, error=error)
        return a

    # -- control -----------------------------------------------------------
    def cancel(self, assessment_id: str) -> str:
        """Cancel a job. Returns ``"cancelled"`` or ``"cancel requested"``."""
        d = self.db.get_assessment(assessment_id)
        if d is None:
            raise JobError(f"no such assessment: {assessment_id}")
        if d["status"] == AssessmentStatus.QUEUED.value and self.db.cancel_queued(
            assessment_id, utcnow().isoformat()
        ):
            self.db.audit(
                self.operator,
                "assessment.cancelled",
                d["target"]["raw"],
                {"assessment_id": assessment_id, "while": "queued"},
            )
            return "cancelled"
        if self.db.request_cancel(assessment_id):
            self.db.audit(
                self.operator,
                "assessment.cancel_requested",
                d["target"]["raw"],
                {"assessment_id": assessment_id},
            )
            return "cancel requested"
        current = self.db.get_assessment(assessment_id) or d
        raise JobError(f"assessment {assessment_id} is already {current['status']}")

    def run_queued(self, limit: int | None = None) -> list[Assessment]:
        """Execute queued assessments oldest-first. Skips ones another worker claimed."""
        done: list[Assessment] = []
        for aid in self.db.list_queued(limit or 1000):
            try:
                done.append(self.execute(aid))
            except JobError:
                continue  # claimed elsewhere or cancelled meanwhile
            if limit is not None and len(done) >= limit:
                break
        return done


__all__ = ["AssessmentEngine", "Target", "assessment_from_dict", "validate_options"]
