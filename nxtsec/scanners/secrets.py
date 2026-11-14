"""Secret detection engine.

Finds likely hardcoded credentials in source text. The cardinal rule: a
detected secret value is NEVER returned in the clear — every match carries a
masked form only (``AKIA************1234``), so matches are safe to log, store
as findings and put in reports.

Two detection strategies:
* typed rules — high-confidence provider patterns (AWS, GitHub, Stripe, ...)
  and a generic ``key = value`` assignment rule for sensitive names;
* entropy — long base64/hex tokens whose Shannon entropy exceeds a threshold,
  caught only when a typed rule did not already claim them.

Obvious placeholders (``your_api_key``, ``xxxxx``, ``changeme``, ...) are
filtered so the signal stays high.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class SecretRule:
    name: str
    description: str
    severity: Severity
    pattern: re.Pattern[str]
    group: int = 0  # capture group holding the secret value
    entropy_min: float | None = None  # extra gate for generic rules


@dataclass(frozen=True)
class SecretMatch:
    rule: str
    description: str
    severity: str
    line: int
    column: int
    masked: str  # the matched secret, masked — never the raw value
    context: str  # the surrounding line, with the secret masked out


_PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|y+|z+|a+|0+|1+|\.+|\*+|<[^>]*>|\{\{?[^}]*\}?\}|\$\{?[^}\s]*\}?|"
    r"your[_-]?\w*|my[_-]?\w*|example\w*|sample\w*|dummy\w*|place?holder\w*|"
    r"test\w*|fake\w*|changeme|change[_-]?me|redacted|none|null|true|false|"
    r"enter[_-]?\w*|insert[_-]?\w*|todo|tbd|xxx+|secret|password|token|apikey|"
    r"api[_-]?key|replace[_-]?\w*)$"
)

MASK_KEEP = 4
MIN_ENTROPY_LEN = 20
DEFAULT_ENTROPY_MIN = 4.0


def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits per character."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask_secret(value: str, keep: int = MASK_KEEP) -> str:
    if len(value) <= keep * 2 + 4:
        return "*" * max(len(value), 8)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'")
    if len(v) < 6:
        return True
    if _PLACEHOLDER.match(v):
        return True
    # a single repeated character, or an obvious non-secret
    return len(set(v)) <= 2


# High-confidence provider rules. Each capture group 0 is the whole token
# unless `group` says otherwise.
RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private_key",
        "PEM private key block",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    ),
    SecretRule(
        "aws_secret_key",
        "AWS secret access key",
        Severity.CRITICAL,
        re.compile(r"(?i)aws.{0,20}?(?:secret|key).{0,5}?[:=]\s*[\"']?" r"([A-Za-z0-9/+=]{40})"),
        group=1,
    ),
    SecretRule(
        "aws_access_key",
        "AWS access key id",
        Severity.HIGH,
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16})\b"),
        group=1,
    ),
    SecretRule(
        "github_token",
        "GitHub token",
        Severity.CRITICAL,
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        group=1,
    ),
    SecretRule(
        "stripe_secret",
        "Stripe secret/restricted key",
        Severity.CRITICAL,
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"),
        group=1,
    ),
    SecretRule(
        "anthropic_key",
        "Anthropic API key",
        Severity.CRITICAL,
        re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"),
        group=1,
    ),
    SecretRule(
        "openai_key",
        "OpenAI API key",
        Severity.CRITICAL,
        re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b"),
        group=1,
    ),
    SecretRule(
        "google_api_key",
        "Google API key",
        Severity.HIGH,
        re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        group=1,
    ),
    SecretRule(
        "slack_token",
        "Slack token",
        Severity.HIGH,
        re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
        group=1,
    ),
    SecretRule(
        "google_oauth",
        "Google OAuth client secret",
        Severity.HIGH,
        re.compile(r"\b(GOCSPX-[A-Za-z0-9_-]{20,})\b"),
        group=1,
    ),
    SecretRule(
        "jwt",
        "JSON Web Token",
        Severity.MEDIUM,
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
        group=1,
    ),
    SecretRule(
        "db_url_password",
        "Password in a database/connection URL",
        Severity.HIGH,
        re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s@\"']{3,})@"),
        group=1,
    ),
    SecretRule(
        "generic_secret",
        "Hardcoded secret assignment",
        Severity.MEDIUM,
        re.compile(
            r"(?i)\b[A-Za-z0-9_.-]*"
            r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
            r"private[_-]?key|client[_-]?secret|auth[_-]?token)"
            r"[A-Za-z0-9_.-]*\s*[:=]\s*[\"']([^\"'\n]{6,})[\"']"
        ),
        group=1,
        entropy_min=2.5,
    ),
    SecretRule(
        "high_entropy",
        "High-entropy string (possible credential)",
        Severity.LOW,
        re.compile(r"[\"']([A-Za-z0-9+/=_-]{20,})[\"']"),
        group=1,
        entropy_min=DEFAULT_ENTROPY_MIN,
    ),
)


def _mask_in_context(line: str, value: str) -> str:
    masked = mask_secret(value)
    return line.strip().replace(value, masked)[:200]


def scan_text(text: str, *, max_line_len: int = 4000) -> list[SecretMatch]:
    """Scan source text and return matches with every secret value masked."""
    matches: list[SecretMatch] = []
    seen: set[tuple[str, int, str]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > max_line_len:
            line = line[:max_line_len]
        # track spans already claimed by a higher-confidence rule on this line
        claimed: list[tuple[int, int]] = []
        for rule in RULES:
            for m in rule.pattern.finditer(line):
                value = m.group(rule.group) if rule.group else m.group(0)
                if not value:
                    continue
                start = m.start(rule.group) if rule.group else m.start(0)
                end = start + len(value)
                if any(s < end and start < e for s, e in claimed):
                    continue  # overlaps a stronger match
                if rule.name in ("generic_secret", "high_entropy") and is_placeholder(value):
                    continue
                if rule.entropy_min is not None and shannon_entropy(value) < rule.entropy_min:
                    continue
                key = (rule.name, lineno, mask_secret(value))
                if key in seen:
                    continue
                seen.add(key)
                claimed.append((start, end))
                matches.append(
                    SecretMatch(
                        rule=rule.name,
                        description=rule.description,
                        severity=rule.severity.value,
                        line=lineno,
                        column=start + 1,
                        masked=mask_secret(value),
                        context=_mask_in_context(line, value),
                    )
                )
    return matches
