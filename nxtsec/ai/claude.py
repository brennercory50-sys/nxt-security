"""Anthropic Claude provider.

Lazily imports the ``anthropic`` SDK so it is an optional dependency — the
platform runs without it. The API key is read from the environment by the SDK
(``ANTHROPIC_API_KEY``); it is never taken from configuration files.
"""

from __future__ import annotations

import os

from nxtsec.ai.base import AIError, AIProvider, AIRequest, AIResponse

DEFAULT_MODEL = "claude-opus-5-5"


class ClaudeProvider(AIProvider):
    name = "claude"

    def __init__(self, model: str = DEFAULT_MODEL, api_key_env: str = "ANTHROPIC_API_KEY") -> None:
        self._model = model
        self._api_key_env = api_key_env

    @property
    def model(self) -> str:
        return self._model

    def available(self) -> tuple[bool, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "the 'anthropic' package is not installed (pip install anthropic)"
        if not os.environ.get(self._api_key_env):
            return False, f"{self._api_key_env} is not set in the environment"
        return True, f"anthropic SDK available, {self._api_key_env} set"

    def complete(self, request: AIRequest) -> AIResponse:
        try:
            import anthropic
        except ImportError as exc:
            raise AIError("the 'anthropic' package is not installed") from exc
        if not os.environ.get(self._api_key_env):
            raise AIError(f"{self._api_key_env} is not set")
        client = anthropic.Anthropic()
        try:
            resp = client.messages.create(
                model=self._model,
                max_tokens=request.max_tokens,
                system=request.system or "You are a precise security analysis assistant.",
                messages=[{"role": "user", "content": request.prompt}],
            )
        except anthropic.APIError as exc:  # pragma: no cover - needs live API
            raise AIError(f"Claude API error: {exc}") from exc
        text = "".join(getattr(b, "text", "") for b in resp.content if b.type == "text")
        stop = getattr(resp, "stop_reason", None)
        usage = {
            "input_tokens": getattr(resp.usage, "input_tokens", 0),
            "output_tokens": getattr(resp.usage, "output_tokens", 0),
        }
        return AIResponse(
            text=text,
            provider=self.name,
            model=self._model,
            truncated=stop == "max_tokens",
            usage=usage,
            meta={"stop_reason": stop},
        )
