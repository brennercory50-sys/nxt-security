"""AI analyst: turn normalized findings into advisory prompts and annotations.

Hard rules enforced here, not left to the caller:
* every finding is REDACTED before it is put in a prompt — secrets never leave
  the process even when the provider is remote;
* AI output is advisory. ``annotate_finding`` attaches the analysis as a note
  through the finding service; it never changes severity or status. A human
  decides.
"""

from __future__ import annotations

import logging
from typing import Any

from nxtsec.ai.base import AIProvider, AIRequest, AIResponse
from nxtsec.findings.service import FindingService
from nxtsec.safety.redaction import redact, redact_obj

log = logging.getLogger("nxtsec.ai")

ADVISORY_BANNER = "AI advisory (not authoritative — verify independently):"

_FINDING_SYSTEM = (
    "You are a senior application security engineer reviewing findings from an "
    "authorized assessment of the operator's own systems. Be concise and concrete. "
    "Explain the risk, assess whether it is likely a true positive, and give specific "
    "remediation steps. You are advising a human analyst who makes the final decision; "
    "never claim certainty you do not have."
)
_SUMMARY_SYSTEM = (
    "You are a security lead writing a short executive summary of assessment findings "
    "for a technical owner. Prioritize by severity, group related issues, and state the "
    "top actions. Keep it under 200 words. This is advisory input, not a final report."
)


def finding_prompt(finding: dict[str, Any]) -> str:
    """Build a redacted prompt describing one finding."""
    f = redact_obj(finding)
    parts = [
        f"Title: {f.get('title', '')}",
        f"Severity: {f.get('severity', '')}  Confidence: {f.get('confidence', '')}",
        f"Target: {f.get('target', '')}",
        f"Detection module: {f.get('detection_module', '')}",
        f"CWE: {f.get('cwe') or 'n/a'}",
    ]
    for label, key in (
        ("Description", "description"),
        ("Impact", "impact"),
        ("Current remediation note", "remediation"),
    ):
        if f.get(key):
            parts.append(f"{label}: {f[key]}")
    parts.append(
        "\nQuestions: (1) Explain the risk in two sentences. (2) Is this likely a true "
        "positive or a false positive, and why? (3) What are the concrete remediation steps?"
    )
    return "\n".join(parts)


def summary_prompt(findings: list[dict[str, Any]]) -> str:
    lines = ["Findings (most severe first):"]
    for f in findings[:60]:
        fr = redact_obj(f)
        lines.append(
            f"- [{fr.get('severity')}] {fr.get('title')} "
            f"({fr.get('detection_module')}, status {fr.get('status')})"
        )
    lines.append("\nWrite a short prioritized summary and the top three recommended actions.")
    return "\n".join(lines)


class AIAnalyst:
    def __init__(self, provider: AIProvider, findings: FindingService, operator: str) -> None:
        self.provider = provider
        self.findings = findings
        self.operator = operator

    def analyze_finding(self, ref: str, *, annotate: bool = False) -> AIResponse:
        finding = self.findings.resolve(ref)
        req = AIRequest(
            prompt=finding_prompt(finding),
            system=_FINDING_SYSTEM,
            max_tokens=1024,
            purpose="analysis",
        )
        resp = self.provider.complete(req)
        self.findings.db.audit(
            self.operator,
            "ai.analyze",
            finding.get("target"),
            {"finding_id": finding["id"], "provider": resp.provider, "model": resp.model},
        )
        if annotate:
            note = f"{ADVISORY_BANNER} [{resp.provider}/{resp.model}]\n{redact(resp.text)}"
            self.findings.add_note(finding["id"], note)
        return resp

    def summarize(self, findings: list[dict[str, Any]]) -> AIResponse:
        req = AIRequest(
            prompt=summary_prompt(findings),
            system=_SUMMARY_SYSTEM,
            max_tokens=1024,
            purpose="summary",
        )
        resp = self.provider.complete(req)
        self.findings.db.audit(
            self.operator,
            "ai.summarize",
            None,
            {"count": len(findings), "provider": resp.provider, "model": resp.model},
        )
        return resp
