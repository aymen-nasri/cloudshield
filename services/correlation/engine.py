"""Correlation rules C-01..C-04.

Rules are tried in order of specificity. An event joins the first open case that holds an
event sharing the rule's key within the rule's time window. Cases never span accounts or
clusters (C-04). If nothing matches, the event opens a new case (rule C-00).
"""

from dataclasses import dataclass
from datetime import timedelta

from cases.models import Case, CaseLink
from cases.store import CaseStore
from common.ids import new_id
from common.models import NormalizedEvent


@dataclass(frozen=True)
class Rule:
    rule_id: str
    key: str  # attribute of CorrelationKeys
    window: timedelta
    confidence: float


RULES: tuple[Rule, ...] = (
    Rule("C-01", "pod_uid", timedelta(minutes=15), 0.9),
    Rule("C-02", "instance_id", timedelta(minutes=30), 0.7),
    Rule("C-03", "principal_arn", timedelta(minutes=60), 0.6),
)


def same_scope(case: Case, event: NormalizedEvent) -> bool:
    """C-04: never merge across account or cluster boundaries."""
    return case.account_id == event.account_id and case.cluster == event.cluster


class CorrelationEngine:
    def __init__(self, cases: CaseStore) -> None:
        self.cases = cases

    def correlate(self, event: NormalizedEvent) -> tuple[Case, CaseLink]:
        for rule in RULES:
            value = getattr(event.keys, rule.key)
            if not value:
                continue
            for case in self.cases.open_cases():
                if not same_scope(case, event):
                    continue
                for member in case.events:
                    if getattr(member.keys, rule.key) != value:
                        continue
                    # abs() so late-arriving events still join: ordering uses event time, not arrival.
                    if abs(member.event_time - event.event_time) <= rule.window:
                        link = CaseLink(
                            event_id=event.event_id,
                            rule=rule.rule_id,
                            confidence=rule.confidence,
                            rationale=(
                                f"shares {rule.key}={value} with {member.event_id} "
                                f"within {int(rule.window.total_seconds() // 60)} min"
                            ),
                        )
                        case.add(event, link)
                        self.cases.save(case)
                        return case, link

        case = Case(
            case_id=new_id("case"),
            title=event.title,
            account_id=event.account_id,
            cluster=event.cluster,
            opened_at=event.ingest_time,
        )
        link = CaseLink(event.event_id, "C-00", 1.0, "first event of a new case")
        case.add(event, link)
        self.cases.save(case)
        return case, link
