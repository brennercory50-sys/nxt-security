"""Small, bounded networking helpers shared by modules and the CLI."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import TypeVar

T = TypeVar("T")


class LookupTimeout(TimeoutError):
    pass


def bounded_call(fn: Callable[[], T], timeout: float) -> T:
    """Run a blocking call (e.g. getaddrinfo, which has no timeout) with a deadline.

    The worker thread may outlive the deadline; its result is discarded.
    """
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="nxtsec-lookup")
    try:
        return pool.submit(fn).result(timeout=timeout)
    except FutureTimeout:
        raise LookupTimeout(f"timed out after {timeout}s") from None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def resolve_host(host: str, timeout: float = 5.0) -> list[str]:
    """Resolve ``host`` to unique IP strings (IPv4 first). IPs are returned unchanged.

    Raises ``socket.gaierror`` on resolution failure and :class:`LookupTimeout`.
    """
    if is_ip(host):
        return [host]
    infos = bounded_call(lambda: socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout)
    seen: dict[str, int] = {}
    for family, _type, _proto, _canon, sockaddr in infos:
        addr = str(sockaddr[0]).split("%", 1)[0]
        seen.setdefault(addr, 0 if family == socket.AF_INET else 1)
    return sorted(seen, key=lambda a: (seen[a], a))
