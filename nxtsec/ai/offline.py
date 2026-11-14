"""Offline, deterministic AI provider — the default.

Needs no network, no API key and no third-party package. It produces a
structured, rule-based analysis from the prompt it is given, so the AI
workflow (and its tests) run anywhere. It is honest about what it is: its
output is labelled as heuristic, not model-generated.
"""

from __future__ import annotations

import re

from nxtsec.ai.base import AIProvider, AIRequest, AIResponse

_WORD = re.compile(r"[A-Za-z][A-Za-z0-9'-]+")


class OfflineProvider(AIProvider):
    name = "offline"

    @property
    def model(self) -> str:
        return "heuristic-v1"

    def available(self) -> tuple[bool, str]:
        return True, "built-in deterministic analyzer (no network, no key)"

    def complete(self, request: AIRequest) -> AIResponse:
        text = self._summarize(request.prompt)
        return AIResponse(
            text=text,
            provider=self.name,
            model=self.model,
            usage={"input_chars": len(request.prompt)},
            meta={"heuristic": True},
        )

    @staticmethod
    def _summarize(prompt: str) -> str:
        lines = [ln.strip() for ln in prompt.splitlines() if ln.strip()]
        head = " ".join(lines[:3])[:400]
        sentences = re.split(r"(?<=[.!?])\s+", head)
        summary = " ".join(sentences[:2]).strip() or "No content to analyze."
        return (
            "[heuristic analysis — not model-generated]\n"
            f"{summary}\n\n"
            "This is a deterministic summary. Configure an AI provider "
            "(ai.provider) for richer analysis. Treat all AI output as advisory: "
            "verify findings independently before acting."
        )
