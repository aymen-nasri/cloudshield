"""Idempotent ingestion: one source event produces at most one normalized event."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from common.ids import new_id
from common.models import NormalizedEvent
from common.timeutil import utcnow
from ingestion.adapters.base import SourceAdapter, dedup_key
from ingestion.evidence import EvidenceStore


class DuplicateEventError(Exception):
    """Raised by an EventStore when the dedup key already exists (the unique-constraint backstop)."""


class EventStore(Protocol):
    def exists(self, dedup_key: str) -> bool: ...

    def insert(self, event: NormalizedEvent, dedup_key: str) -> None: ...

    def get(self, event_id: str) -> NormalizedEvent | None: ...


class InMemoryEventStore:
    """Dev/test store. storage.postgres.PostgresEventStore is the persistent implementation."""

    def __init__(self) -> None:
        self._by_key: dict[str, NormalizedEvent] = {}
        self._by_id: dict[str, NormalizedEvent] = {}

    def exists(self, dedup_key: str) -> bool:
        return dedup_key in self._by_key

    def insert(self, event: NormalizedEvent, dedup_key: str) -> None:
        if dedup_key in self._by_key:
            raise DuplicateEventError(dedup_key)
        self._by_key[dedup_key] = event
        self._by_id[event.event_id] = event

    def get(self, event_id: str) -> NormalizedEvent | None:
        return self._by_id.get(event_id)

    def all(self) -> list[NormalizedEvent]:
        return list(self._by_id.values())


@dataclass(frozen=True)
class IngestResult:
    status: Literal["accepted", "duplicate"]
    dedup_key: str
    event_id: str | None = None


class IngestPipeline:
    def __init__(
        self,
        events: EventStore,
        evidence: EvidenceStore,
        on_accepted: Callable[[NormalizedEvent], None] | None = None,
        clock: Callable[[], datetime] = utcnow,
        enrich: Callable[[NormalizedEvent], NormalizedEvent] | None = None,
    ) -> None:
        self.events = events
        self.evidence = evidence
        self.on_accepted = on_accepted
        self.clock = clock
        self.enrich = enrich

    def ingest(self, raw: bytes, adapter: SourceAdapter) -> IngestResult:
        payload = adapter.parse(raw)
        key = dedup_key(adapter.name, adapter.source_event_id(payload))
        if self.events.exists(key):
            return IngestResult("duplicate", key)

        now = self.clock()
        uri, checksum = self.evidence.archive(adapter.name, raw, now)
        event = adapter.to_event(
            payload, event_id=new_id("evt"), ingest_time=now, raw_uri=uri, checksum=checksum
        )
        if self.enrich:
            # Before insert, so the stored event and correlation both see resolved identity and keys.
            event = self.enrich(event)
        try:
            self.events.insert(event, key)
        except DuplicateEventError:
            # Lost a race with a concurrent delivery of the same event.
            return IngestResult("duplicate", key)

        if self.on_accepted:
            self.on_accepted(event)
        return IngestResult("accepted", key, event.event_id)
