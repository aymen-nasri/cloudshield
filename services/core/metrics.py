"""Prometheus metrics about CloudShield itself: operational health, separate from threat alerts.

Label values only ever come from fixed lists in this code (adapters, allowlisted actions, check
names), never from a request or an alert, so nothing an attacker sends can create new series.
"""

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from common.models import NormalizedEvent
from ingestion.coverage import CoverageTracker
from response.records import ProposalRecord

LAG_BUCKETS = (1, 5, 15, 60, 300, 900, 3600)
RESPONSE_BUCKETS = (1, 5, 15, 60, 300, 900, 3600, 14400)
CHECK_RESULTS = {True: "passed", False: "failed", None: "skipped"}


class Metrics:
    def __init__(self, coverage: CoverageTracker) -> None:
        self.coverage = coverage
        self.registry = CollectorRegistry()  # per app, so several apps can exist in one process
        self.ingest_events = Counter(
            "cloudshield_ingest_events",
            "Alerts received, by source and what happened to them.",
            ["source", "result"],
            registry=self.registry,
        )
        self.ingest_lag = Histogram(
            "cloudshield_ingest_lag_seconds",
            "Time from the event happening to CloudShield receiving it.",
            ["source"],
            buckets=LAG_BUCKETS,
            registry=self.registry,
        )
        self.executions = Counter(
            "cloudshield_response_executions",
            "Response actions that finished, by outcome.",
            ["action_type", "outcome"],
            registry=self.registry,
        )
        self.response_duration = Histogram(
            "cloudshield_response_duration_seconds",
            "Time from a proposal being created to its action finishing.",
            ["action_type"],
            buckets=RESPONSE_BUCKETS,
            registry=self.registry,
        )
        self.verification_checks = Counter(
            "cloudshield_verification_checks",
            "Post-action verification checks. A skipped check proved nothing.",
            ["check", "result"],
            registry=self.registry,
        )
        self.heartbeat_age = Gauge(
            "cloudshield_source_heartbeat_age_seconds",
            "Seconds since the last alert from this source.",
            ["source"],
            registry=self.registry,
        )
        self.degraded = Gauge(
            "cloudshield_source_degraded",
            "1 if this source is silent or was never seen: no alerts does not mean no attacks.",
            ["source"],
            registry=self.registry,
        )

    def observe_event(self, event: NormalizedEvent) -> None:
        lag = (event.ingest_time - event.event_time).total_seconds()
        self.ingest_lag.labels(event.source).observe(max(lag, 0))  # the source's clock can run ahead

    def observe_response(self, record: ProposalRecord) -> None:
        action = record.proposal.action_type
        self.executions.labels(action, record.state.value).inc()
        execution = record.execution
        if execution is None:
            return
        if execution.finished_at:
            duration = (execution.finished_at - record.proposal.created_at).total_seconds()
            self.response_duration.labels(action).observe(max(duration, 0))
        for check, passed in (execution.checks or {}).items():
            self.verification_checks.labels(check, CHECK_RESULTS[passed]).inc()

    def render(self) -> bytes:
        for source, status in self.coverage.status().items():
            self.degraded.labels(source).set(0 if status["state"] == "ok" else 1)
            if status["age_seconds"] is not None:
                self.heartbeat_age.labels(source).set(status["age_seconds"])
        return generate_latest(self.registry)
