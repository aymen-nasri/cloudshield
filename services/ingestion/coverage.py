"""Sensor coverage. A silent source is reported as degraded, never as a quiet, safe environment."""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from common.timeutil import utcnow


class CoverageTracker:
    def __init__(
        self, expected: dict[str, timedelta], clock: Callable[[], datetime] = utcnow
    ) -> None:
        self.expected = expected
        self.clock = clock
        self.last_seen: dict[str, datetime] = {}

    def heartbeat(self, source: str, at: datetime | None = None) -> None:
        self.last_seen[source] = at or self.clock()

    def status(self) -> dict[str, dict[str, Any]]:
        now = self.clock()
        report: dict[str, dict[str, Any]] = {}
        for source, max_silence in self.expected.items():
            seen = self.last_seen.get(source)
            if seen is None:
                report[source] = {"state": "unknown", "last_seen": None, "age_seconds": None}
                continue
            age = now - seen
            report[source] = {
                "state": "ok" if age <= max_silence else "degraded",
                "last_seen": seen.isoformat(),
                "age_seconds": int(age.total_seconds()),
            }
        return report

    def overall(self) -> str:
        states = {s["state"] for s in self.status().values()}
        return "ok" if states <= {"ok"} else "degraded"
