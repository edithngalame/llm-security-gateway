"""In-memory stream of gateway decisions, for the live dashboard.

Privacy: by default an event holds only metadata (action, score, source,
categories, latency), never the text. Set GW_DEMO_MODE=1 to also store a short
preview. Use that only with synthetic or test traffic, never real users.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass

PREVIEW_CHARS = 90


def demo_mode() -> bool:
    return os.getenv("GW_DEMO_MODE", "0") == "1"


@dataclass(frozen=True)
class Event:
    id: int
    ts: float
    action: str
    score: float
    source: str
    categories: list[str]
    latency_ms: float
    preview: str | None = None


class EventLog:
    """Thread-safe ring buffer: keeps the newest `maxlen` events and running totals."""

    def __init__(self, maxlen: int = 500):
        self._events: deque[Event] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._next_id = 1
        self._totals: dict[str, int] = {"allow": 0, "flag": 0, "block": 0}

    def record(self, action: str, score: float, source: str, categories: list[str],
               latency_ms: float, text: str | None = None) -> Event:
        preview = None
        if text is not None and demo_mode():
            flat = " ".join(text.split())
            preview = flat[:PREVIEW_CHARS] + ("…" if len(flat) > PREVIEW_CHARS else "")
        with self._lock:
            event = Event(self._next_id, time.time(), action, score, source,
                          categories, latency_ms, preview)
            self._next_id += 1
            self._events.append(event)
            self._totals[action] = self._totals.get(action, 0) + 1
        return event

    def since(self, after_id: int = 0, limit: int = 200) -> list[dict]:
        with self._lock:
            new = [e for e in self._events if e.id > after_id]
        return [asdict(e) for e in new[-limit:]]

    def stats(self) -> dict:
        with self._lock:
            latencies = sorted(e.latency_ms for e in self._events)
            totals = dict(self._totals)
        p95 = latencies[min(len(latencies) - 1, int(0.95 * len(latencies)))] if latencies else 0.0
        return {"totals": totals, "total": sum(totals.values()), "p95_latency_ms": p95,
                "demo_mode": demo_mode()}
