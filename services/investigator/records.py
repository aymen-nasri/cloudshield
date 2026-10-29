"""Stored investigations and the in-memory store."""

import threading
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Literal, Protocol

from common.models import Investigation

ReviewStatus = Literal["unreviewed", "accepted", "rejected"]


@dataclass
class InvestigationRecord:
    investigation_id: str
    case_id: str
    model_id: str
    prompt_version: str
    retrieved_doc_ids: list[str]
    output: Investigation
    attempts: int
    requested_by: str
    created_at: datetime
    review_status: ReviewStatus = "unreviewed"
    reviewed_by: str | None = None

    def view(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "case_id": self.case_id,
            "model_id": self.model_id,
            "prompt_version": self.prompt_version,
            "retrieved_doc_ids": self.retrieved_doc_ids,
            "attempts": self.attempts,
            "requested_by": self.requested_by,
            "created_at": self.created_at.isoformat(),
            "review_status": self.review_status,
            "reviewed_by": self.reviewed_by,
            "output": self.output.model_dump(mode="json"),
        }


class InvestigationStore(Protocol):
    def insert(self, record: InvestigationRecord) -> None: ...

    def get(self, investigation_id: str) -> InvestigationRecord | None: ...

    def list_for_case(self, case_id: str) -> list[InvestigationRecord]: ...

    def set_review(self, investigation_id: str, status: ReviewStatus, reviewer: str) -> bool:
        """Record a review once. False if it was already reviewed."""
        ...


class InMemoryInvestigationStore:
    def __init__(self) -> None:
        self._records: dict[str, InvestigationRecord] = {}
        self._lock = threading.Lock()

    def insert(self, record: InvestigationRecord) -> None:
        with self._lock:
            self._records[record.investigation_id] = replace(record)

    def get(self, investigation_id: str) -> InvestigationRecord | None:
        record = self._records.get(investigation_id)
        return replace(record) if record else None

    def list_for_case(self, case_id: str) -> list[InvestigationRecord]:
        found = [replace(r) for r in self._records.values() if r.case_id == case_id]
        return sorted(found, key=lambda r: r.created_at)

    def set_review(self, investigation_id: str, status: ReviewStatus, reviewer: str) -> bool:
        with self._lock:
            record = self._records[investigation_id]
            if record.review_status != "unreviewed":
                return False
            record.review_status, record.reviewed_by = status, reviewer
            return True
