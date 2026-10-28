"""Post-validation outside the model: structure, citations and targets."""

import json
import re

from pydantic import ValidationError

from common.models import Investigation
from investigator.bundle import EvidenceBundle

_FENCE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.S)


class InvestigationRejected(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def citation_problems(inv: Investigation, bundle: EvidenceBundle) -> list[str]:
    known_events = bundle.event_ids
    known_entities = bundle.entity_ids
    problems: list[str] = []

    for i, fact in enumerate(inv.observed_facts):
        unknown = set(fact.evidence_ids) - known_events
        if unknown:
            problems.append(f"fact {i} cites unknown evidence {sorted(unknown)}")
    for i, hyp in enumerate(inv.hypotheses):
        unknown = (set(hyp.supporting_evidence) | set(hyp.contradicting_evidence)) - known_events
        if unknown:
            problems.append(f"hypothesis {i} cites unknown evidence {sorted(unknown)}")
    for i, option in enumerate(inv.containment_options):
        if option.target_entity_id not in known_entities:
            problems.append(f"containment option {i} targets unknown entity {option.target_entity_id!r}")
    return problems


def parse_and_validate(text: str, bundle: EvidenceBundle) -> Investigation:
    match = _FENCE.search(text)
    raw = match.group(1) if match else text.strip()
    try:
        inv = Investigation.model_validate(json.loads(raw))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise InvestigationRejected([f"output does not match the investigation schema: {exc}"]) from exc

    problems = citation_problems(inv, bundle)
    if problems:
        raise InvestigationRejected(problems)
    return inv
