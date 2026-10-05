"""Secret redaction.

Applied to every log record and to any text that leaves the process (reports,
JSON output). Detected secrets are never printed; only a short prefix/suffix
survives so an operator can tell *which* credential leaked.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._~+/-]{12,}=*")),
    # credentials embedded in URLs: scheme://user:PASSWORD@host
    ("url_password", re.compile(r"(?<=://)[^/\s:@]+:([^/\s@]+)(?=@)")),
    # key=value / key: value assignments with sensitive key names
    (
        "assignment",
        re.compile(
            r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"
            r"access[_-]?key|private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_.-]*)"
            r"(\s*[:=]\s*[\"']?)([^\s\"',;]{4,})"
        ),
    ),
]

SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|credential|auth)"
)


def mask(value: str, keep: int = 4) -> str:
    """``sk_live_abcdefgh12345678`` -> ``sk_l****************5678``."""
    if len(value) <= keep * 2 + 4:
        return "*" * max(len(value), 8)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def redact(text: str) -> str:
    if not text:
        return text
    for name, pat in _PATTERNS:
        if name == "private_key":
            text = pat.sub("[REDACTED PRIVATE KEY]", text)
        elif name == "assignment":
            text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{mask(m.group(3))}", text)
        elif name == "url_password":
            text = pat.sub(lambda m: m.group(0).split(":", 1)[0] + ":" + mask(m.group(1)), text)
        else:
            text = pat.sub(lambda m: mask(m.group(0)), text)
    return text


def redact_obj(obj: Any) -> Any:
    """Recursively redact strings in JSON-like structures; mask values under sensitive keys."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, Mapping):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and SENSITIVE_KEY.search(k) and isinstance(v, str) and v:
                out[k] = mask(v)
            else:
                out[k] = redact_obj(v)
        return out
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact_obj(v) for v in obj)
    return obj
