"""OpenAI-compatible provider — covers OpenAI and local models.

Uses the ``openai`` SDK (lazily imported) against the standard Chat
Completions API. Point ``base_url`` at a local server (Ollama, LM Studio,
vLLM) to run a local model through the same adapter. The API key is read from
the environment only.
"""

from __future__ import annotations

import os

from nxtsec.ai.base import AIError, AIProvider, AIRequest, AIResponse


class OpenAICompatProvider(AIProvider):
    name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key_env: str = "OPENAI_API_KEY",
        base_url: str | None = None,
    ) -> None:
        self._model = model
        self._api_key_env = api_key_env
        self._base_url = base_url

    @property
    def model(self) -> str:
        return self._model

    def available(self) -> tuple[bool, str]:
        try:
            import openai  # noqa: F401
        except ImportError:
            return False, "the 'openai' package is not installed (pip install openai)"
        # a local base_url may not need a key
        if not self._base_url and not os.environ.get(self._api_key_env):
            return False, f"{self._api_key_env} is not set in the environment"
        where = self._base_url or "api.openai.com"
        return True, f"openai SDK available, endpoint {where}"

    def complete(self, request: AIRequest) -> AIResponse:
        try:
            import openai
        except ImportError as exc:
            raise AIError("the 'openai' package is not installed") from exc
        key = os.environ.get(self._api_key_env) or ("local" if self._base_url else None)
        if not key:
            raise AIError(f"{self._api_key_env} is not set")
        client = openai.OpenAI(api_key=key, base_url=self._base_url)
        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})
        try:
            resp = client.chat.completions.create(
                model=self._model,
                max_tokens=request.max_tokens,
                temperature=request.temperature if request.temperature is not None else 0.2,
                messages=messages,
            )
        except openai.OpenAIError as exc:  # pragma: no cover - needs live API
            raise AIError(f"OpenAI API error: {exc}") from exc
        choice = resp.choices[0]
        usage = {}
        if resp.usage:
            usage = {
                "input_tokens": resp.usage.prompt_tokens,
                "output_tokens": resp.usage.completion_tokens,
            }
        return AIResponse(
            text=choice.message.content or "",
            provider=self.name,
            model=self._model,
            truncated=choice.finish_reason == "length",
            usage=usage,
            meta={"finish_reason": choice.finish_reason, "base_url": self._base_url},
        )
