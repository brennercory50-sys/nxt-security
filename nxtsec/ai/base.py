"""The AI provider contract.

Every adapter implements :meth:`AIProvider.complete`. Requests and responses
are plain dataclasses so the rest of the platform never touches a vendor SDK
type. Providers must not raise vendor exceptions past this boundary — they
wrap them in :class:`AIError`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from nxtsec.core.errors import NxtSecError


class AIError(NxtSecError):
    """An AI provider was misconfigured or a completion failed."""


@dataclass
class AIRequest:
    prompt: str
    system: str = ""
    max_tokens: int = 2048
    temperature: float | None = None  # None = provider default
    purpose: str = "analysis"  # analysis | summary | triage — for logging/audit


@dataclass
class AIResponse:
    text: str
    provider: str
    model: str
    truncated: bool = False
    usage: dict[str, int] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)


class AIProvider(ABC):
    """Base class for AI adapters."""

    name: str = "base"

    @property
    @abstractmethod
    def model(self) -> str: ...

    @abstractmethod
    def available(self) -> tuple[bool, str]:
        """Return ``(ready, detail)`` — whether this provider can run, and why/why not."""

    @abstractmethod
    def complete(self, request: AIRequest) -> AIResponse:
        """Return a completion, or raise :class:`AIError`."""

    def describe(self) -> dict[str, Any]:
        ready, detail = self.available()
        return {"provider": self.name, "model": self.model, "ready": ready, "detail": detail}
