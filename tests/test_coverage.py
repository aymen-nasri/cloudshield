from datetime import UTC, datetime, timedelta

from ingestion.coverage import CoverageTracker

T0 = datetime(2026, 10, 28, 14, 0, tzinfo=UTC)


def test_source_becomes_degraded_after_max_silence():
    now = [T0]
    tracker = CoverageTracker({"falco": timedelta(minutes=5)}, clock=lambda: now[0])
    tracker.heartbeat("falco")
    assert tracker.status()["falco"]["state"] == "ok"

    now[0] = T0 + timedelta(minutes=7)
    assert tracker.status()["falco"]["state"] == "degraded"
    assert tracker.overall() == "degraded"
