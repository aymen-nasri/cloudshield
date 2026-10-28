"""Append-only, hash-chained audit log.

Each record's hash covers its content and the previous record's hash, so editing or deleting
any record breaks every hash after it. verify() finds the first broken link.
"""

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from common.timeutil import utcnow

GENESIS_HASH = "sha256:" + "0" * 64

ActorType = Literal["human", "service", "model"]


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: str
    actor_type: ActorType
    actor_id: str
    action: str
    details: dict[str, Any]
    prev_hash: str
    hash: str


def _digest(
    seq: int, ts: str, actor_type: str, actor_id: str, action: str, details: dict[str, Any], prev_hash: str
) -> str:
    body = json.dumps(
        [seq, ts, actor_type, actor_id, action, details, prev_hash],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()


class AuditStore(Protocol):
    def append(
        self, actor_type: ActorType, actor_id: str, action: str, details: dict[str, Any]
    ) -> AuditRecord: ...

    def records(self, case_id: str | None = None) -> list[AuditRecord]: ...

    def verify(self) -> int | None: ...


def make_record(
    seq: int,
    at: datetime,
    actor_type: ActorType,
    actor_id: str,
    action: str,
    details: dict[str, Any],
    prev_hash: str,
) -> AuditRecord:
    ts = format_ts(at)
    return AuditRecord(
        seq=seq,
        ts=ts,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        details=details,
        prev_hash=prev_hash,
        hash=_digest(seq, ts, actor_type, actor_id, action, details, prev_hash),
    )


def format_ts(at: datetime) -> str:
    """Canonical timestamp text: UTC, microseconds. Stores must round-trip this exactly."""
    return at.astimezone(UTC).isoformat(timespec="microseconds")


class AuditLog:
    def __init__(self, clock: Callable[[], datetime] = utcnow) -> None:
        self._records: list[AuditRecord] = []
        self.clock = clock

    def append(
        self, actor_type: ActorType, actor_id: str, action: str, details: dict[str, Any]
    ) -> AuditRecord:
        prev = self._records[-1].hash if self._records else GENESIS_HASH
        record = make_record(
            len(self._records) + 1, self.clock(), actor_type, actor_id, action, details, prev
        )
        self._records.append(record)
        return record

    def records(self, case_id: str | None = None) -> list[AuditRecord]:
        if case_id is None:
            return list(self._records)
        return [r for r in self._records if r.details.get("case_id") == case_id]

    def verify(self) -> int | None:
        """Return the seq of the first tampered record, or None if the chain is intact."""
        return verify_chain(self._records)


def verify_chain(records: list[AuditRecord]) -> int | None:
    prev = GENESIS_HASH
    for r in records:
        expected = _digest(r.seq, r.ts, r.actor_type, r.actor_id, r.action, r.details, prev)
        if r.prev_hash != prev or r.hash != expected:
            return r.seq
        prev = r.hash
    return None


def to_dict(record: AuditRecord) -> dict[str, Any]:
    return asdict(record)
