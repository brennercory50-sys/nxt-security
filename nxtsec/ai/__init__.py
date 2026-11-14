"""Provider-agnostic AI analysis layer.

AI output in NXT-Security is strictly ADVISORY: it annotates findings and
writes summaries, but never creates, re-severities, or changes the status of a
finding on its own. A human always decides. No provider is hard-coded; the
active one is chosen by configuration, and API keys come only from the
environment, never from YAML.
"""

from nxtsec.ai.base import AIError, AIProvider, AIRequest, AIResponse
from nxtsec.ai.factory import available_providers, build_provider
from nxtsec.ai.offline import OfflineProvider

__all__ = [
    "AIError",
    "AIProvider",
    "AIRequest",
    "AIResponse",
    "OfflineProvider",
    "available_providers",
    "build_provider",
]
