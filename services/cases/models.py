from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from common.models import NormalizedEvent, Severity

_SEVERITY_ORDER = list(Severity)


@dataclass(frozen=True)
class CaseLink:
    event_id: str
    rule: str
    confidence: float
    rationale: str


@dataclass
class Case:
    case_id: str
    title: str
    account_id: str | None
    cluster: str | None
    opened_at: datetime
    status: str = "open"
    events: list[NormalizedEvent] = field(default_factory=list)
    links: list[CaseLink] = field(default_factory=list)

    def add(self, event: NormalizedEvent, link: CaseLink) -> None:
        self.events.append(event)
        self.links.append(link)

    @property
    def severity(self) -> Severity:
        return max((e.severity.normalized for e in self.events), key=_SEVERITY_ORDER.index)

    def timeline(self) -> list[NormalizedEvent]:
        """Ordered by when activity happened, not when CloudShield received it."""
        return sorted(self.events, key=lambda e: e.event_time)

    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity.value,
            "account_id": self.account_id,
            "cluster": self.cluster,
            "opened_at": self.opened_at.isoformat(),
            "event_count": len(self.events),
        }
