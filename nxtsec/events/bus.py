"""A small synchronous publish/subscribe bus.

Subsystems (jobs, evidence, findings, correlation) are decoupled through
events such as ``assessment.started`` or ``finding.created``. A failing
subscriber is logged and isolated; it never breaks the publisher.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from nxtsec.core.ids import utcnow

log = logging.getLogger("nxtsec.events")


@dataclass(frozen=True)
class Event:
    name: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=utcnow)


Handler = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, name: str, handler: Handler) -> Callable[[], None]:
        """Subscribe to ``name`` (or ``"*"`` for all). Returns an unsubscribe function."""
        with self._lock:
            self._subs[name].append(handler)

        def _unsub() -> None:
            with self._lock:
                if handler in self._subs[name]:
                    self._subs[name].remove(handler)

        return _unsub

    def publish(self, name: str, **payload: Any) -> Event:
        ev = Event(name, payload)
        with self._lock:
            handlers = [*self._subs.get(name, []), *self._subs.get("*", [])]
        for h in handlers:
            try:
                h(ev)
            except Exception:  # noqa: BLE001 - isolate subscriber failures
                log.exception("event handler failed", extra={"event": name})
        return ev
