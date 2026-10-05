"""Parse operator-supplied strings into validated :class:`Target` objects.

Parsing is strict: anything ambiguous or malformed raises :class:`TargetError`
instead of being guessed at.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from nxtsec.core.errors import TargetError
from nxtsec.core.models import Target, TargetType

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*\.?$")
_LAB_RE = re.compile(r"^lab:[a-z0-9][a-z0-9_-]{0,63}$")
_MAX_LEN = 2048


def _normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _validate_hostname(host: str) -> str:
    h = _normalize_host(host)
    if not h or len(h) > 253 or not _HOSTNAME_RE.match(h):
        raise TargetError(f"invalid hostname: {host!r}")
    return h


def parse_target(raw: str, *, allow_files: bool = True) -> Target:
    """Classify and validate ``raw``.

    Recognized forms: ``lab:<id>``, ``file:<path>``, URLs (http/https),
    CIDR ranges, IPv4/IPv6 addresses, dotted domains and single-label hostnames.
    """
    if not isinstance(raw, str):
        raise TargetError("target must be a string")
    s = raw.strip()
    if not s:
        raise TargetError("target is empty")
    if len(s) > _MAX_LEN:
        raise TargetError("target is too long")
    if any(c in s for c in ("\x00", "\n", "\r")):
        raise TargetError("target contains control characters")

    if s.startswith("lab:"):
        if not _LAB_RE.match(s):
            raise TargetError(f"invalid lab identifier: {s!r}")
        return Target(raw=raw, type=TargetType.LAB, value=s[4:])

    if s.startswith("file:"):
        if not allow_files:
            raise TargetError("file targets are not permitted here")
        p = s[5:]
        if not p:
            raise TargetError("file target has no path")
        return Target(raw=raw, type=TargetType.FILE, value=str(Path(p).expanduser()))

    if "://" in s:
        parts = urlsplit(s)
        if parts.scheme not in ("http", "https"):
            raise TargetError(f"unsupported URL scheme: {parts.scheme!r}")
        if parts.username or parts.password:
            raise TargetError("URLs with embedded credentials are rejected")
        try:
            hostname = parts.hostname
            _ = parts.port  # raises ValueError on a bad port
        except ValueError as exc:
            raise TargetError(f"invalid URL: {exc}") from exc
        if not hostname:
            raise TargetError("URL has no host")
        try:
            host = str(ipaddress.ip_address(hostname))
        except ValueError:
            host = _validate_hostname(hostname)
        return Target(raw=raw, type=TargetType.URL, value=s, host=host)

    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as exc:
            raise TargetError(f"invalid CIDR: {s!r}") from exc
        return Target(raw=raw, type=TargetType.CIDR, value=str(net), host=str(net))

    try:
        ip = ipaddress.ip_address(s.strip("[]"))
    except ValueError:
        pass
    else:
        t = TargetType.IPV4 if ip.version == 4 else TargetType.IPV6
        return Target(raw=raw, type=t, value=str(ip), host=str(ip))

    host = _validate_hostname(s)
    t = TargetType.DOMAIN if "." in host else TargetType.HOSTNAME
    return Target(raw=raw, type=t, value=host, host=host)
