"""Build the configured AI provider.

Provider and model come from settings (``ai.provider``, ``ai.model``,
``ai.base_url``); the key env-var name may be configured but the key value is
only ever read from the environment. Unknown providers fall back to offline
with a warning rather than failing the whole platform.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from nxtsec.ai.base import AIProvider
from nxtsec.ai.offline import OfflineProvider

if TYPE_CHECKING:
    from nxtsec.config.settings import Settings

log = logging.getLogger("nxtsec.ai")

PROVIDERS = ("offline", "claude", "openai", "local")


def available_providers() -> tuple[str, ...]:
    return PROVIDERS


def build_provider(settings: Settings) -> AIProvider:
    name = str(settings.get("ai.provider", "offline") or "offline").lower()
    model = settings.get("ai.model")
    if name in ("offline", "", "none", "null"):
        return OfflineProvider()
    if name == "claude":
        from nxtsec.ai.claude import DEFAULT_MODEL, ClaudeProvider

        return ClaudeProvider(model=str(model or DEFAULT_MODEL))
    if name in ("openai", "local"):
        from nxtsec.ai.openai_compat import OpenAICompatProvider

        base_url = settings.get("ai.base_url")
        if name == "local" and not base_url:
            base_url = "http://localhost:11434/v1"  # Ollama default
        key_env = str(settings.get("ai.api_key_env") or "OPENAI_API_KEY")
        return OpenAICompatProvider(
            model=str(model or ("llama3" if name == "local" else "gpt-4o-mini")),
            api_key_env=key_env,
            base_url=str(base_url) if base_url else None,
        )
    log.warning("unknown ai.provider %r; using offline analyzer", name)
    return OfflineProvider()
