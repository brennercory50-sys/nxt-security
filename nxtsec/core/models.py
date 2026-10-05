"""Normalized domain model.

Every module produces these objects instead of raw tool output, so the
evidence store, finding engine, correlation engine and reporters all speak
one language.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from nxtsec.core.ids import isoformat, new_id, utcnow


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Confidence(str, Enum):
    TENTATIVE = "TENTATIVE"
    FIRM = "FIRM"
    CONFIRMED = "CONFIRMED"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATED = "MITIGATED"
    ACCEPTED = "ACCEPTED"
    CLOSED = "CLOSED"


class AssessmentStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (
            AssessmentStatus.COMPLETED,
            AssessmentStatus.FAILED,
            AssessmentStatus.CANCELLED,
        )

    def can_transition(self, to: AssessmentStatus) -> bool:
        return to in _TRANSITIONS.get(self, frozenset())


_TRANSITIONS: dict[AssessmentStatus, frozenset[AssessmentStatus]] = {
    AssessmentStatus.QUEUED: frozenset({AssessmentStatus.RUNNING, AssessmentStatus.CANCELLED}),
    AssessmentStatus.RUNNING: frozenset(
        {AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED}
    ),
}


class Mode(str, Enum):
    """LAB and REAL target modes are kept strictly separate."""

    REAL = "real"
    LAB = "lab"


class TargetType(str, Enum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    CIDR = "cidr"
    FILE = "file"
    LAB = "lab"


@dataclass(frozen=True)
class Target:
    """A single normalized target. ``host`` is the network identity used for scope checks."""

    raw: str
    type: TargetType
    value: str
    host: str | None = None

    @property
    def is_network(self) -> bool:
        return self.type not in (TargetType.FILE, TargetType.LAB)

    def to_dict(self) -> dict[str, Any]:
        return {"raw": self.raw, "type": self.type.value, "value": self.value, "host": self.host}


@dataclass
class Evidence:
    type: str
    source: str
    description: str
    content_sha256: str
    location: str | None = None
    target: str | None = None
    assessment_id: str | None = None
    id: str = field(default_factory=lambda: new_id("evd"))
    created_at: datetime = field(default_factory=utcnow)
    custody: list[dict[str, str]] = field(default_factory=list)

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["created_at"] = isoformat(self.created_at)
        return d


@dataclass
class Finding:
    title: str
    severity: Severity
    target: str
    detection_module: str
    description: str = ""
    confidence: Confidence = Confidence.TENTATIVE
    component: str | None = None
    cwe: str | None = None
    cvss: float | None = None
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    assessment_id: str | None = None
    id: str = field(default_factory=lambda: new_id("fnd"))
    created_at: datetime = field(default_factory=utcnow)

    @property
    def fingerprint(self) -> str:
        """Stable identity used for deduplication across assessments."""
        key = json.dumps(
            [self.detection_module, self.title.lower(), self.target.lower(), self.component or ""],
        )
        return hashlib.sha256(key.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["status"] = self.status.value
        d["created_at"] = isoformat(self.created_at)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class Assessment:
    target: Target
    operator: str
    modules: list[str]
    mode: Mode = Mode.REAL
    scope_name: str = "default"
    scope_fingerprint: str | None = None
    options: dict[str, str] = field(default_factory=dict)
    status: AssessmentStatus = AssessmentStatus.QUEUED
    id: str = field(default_factory=lambda: new_id("asm"))
    created_at: datetime = field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target.to_dict(),
            "operator": self.operator,
            "modules": list(self.modules),
            "mode": self.mode.value,
            "scope_name": self.scope_name,
            "scope_fingerprint": self.scope_fingerprint,
            "options": dict(self.options),
            "status": self.status.value,
            "created_at": isoformat(self.created_at),
            "started_at": isoformat(self.started_at),
            "finished_at": isoformat(self.finished_at),
            "error": self.error,
        }

    def transition(self, to: AssessmentStatus) -> None:
        if not self.status.can_transition(to):
            raise ValueError(f"illegal assessment transition {self.status.value} -> {to.value}")
        self.status = to
