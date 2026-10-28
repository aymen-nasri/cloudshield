"""Evidence bundles: bounded, redacted, and clearly marked as untrusted data."""

import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from cases.models import Case

MAX_EVENTS = 50
MAX_FIELD_CHARS = 2000

_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
]


def redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text[:MAX_FIELD_CHARS]


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


@dataclass
class EvidenceBundle:
    case_id: str
    events: list[dict[str, Any]]
    entities: list[dict[str, Any]] = field(default_factory=list)
    runbook_passages: list[dict[str, Any]] = field(default_factory=list)

    @property
    def event_ids(self) -> set[str]:
        return {e["event_id"] for e in self.events}

    @property
    def entity_ids(self) -> set[str]:
        return {e["entity_id"] for e in self.entities}


def build_bundle(
    case: Case,
    entities: list[dict[str, Any]] | None = None,
    runbook_passages: list[dict[str, Any]] | None = None,
) -> EvidenceBundle:
    events = []
    for e in case.timeline()[-MAX_EVENTS:]:
        events.append(
            _clean(
                {
                    "event_id": e.event_id,
                    "source": e.source,
                    "event_time": e.event_time.isoformat(),
                    "title": e.title,
                    "event_type": e.event_type,
                    "severity": e.severity.normalized.value,
                    "resource_id": e.resource_id,
                    "namespace": e.namespace,
                    "details": e.ocsf.get("unmapped", {}),
                }
            )
        )
    return EvidenceBundle(
        case_id=case.case_id,
        events=events,
        entities=_clean(entities or []),
        runbook_passages=runbook_passages or [],
    )


def render_untrusted(bundle: EvidenceBundle) -> str:
    """Wrap evidence in tags carrying a random nonce, so text inside an event cannot close the block."""
    nonce = secrets.token_hex(8)
    body = json.dumps(
        {"case_id": bundle.case_id, "events": bundle.events, "entities": bundle.entities},
        indent=2,
    )
    runbooks = json.dumps(bundle.runbook_passages, indent=2)
    return (
        f'<untrusted_evidence nonce="{nonce}">\n{body}\n</untrusted_evidence nonce="{nonce}">\n\n'
        f'<reference_runbooks nonce="{nonce}">\n{runbooks}\n</reference_runbooks nonce="{nonce}">'
    )
