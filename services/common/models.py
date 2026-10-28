"""Core data contracts: normalized events, AI investigations and response proposals.

These models are the boundary between services. JSON Schemas in /schemas are
generated from them (scripts/export_schemas.py), so this file is the source of truth.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "cloudshield-ocsf-subset/1.0 (OCSF 1.3.0)"

EventSource = Literal["falco", "wazuh", "guardduty", "k8s_audit"]


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


OCSF_SEVERITY_ID: dict[Severity, int] = {
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class SeverityInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    normalized: Severity
    original: str


class CorrelationKeys(BaseModel):
    """Stable identifiers the correlation engine joins on (rules C-01..C-03)."""

    model_config = ConfigDict(frozen=True)

    pod_uid: str | None = None
    instance_id: str | None = None
    principal_arn: str | None = None


class NormalizedEvent(BaseModel):
    """Minimum event record. The raw payload is never modified; it is referenced by URI + checksum."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    source: EventSource
    source_event_id: str
    schema_version: str = SCHEMA_VERSION
    event_time: datetime
    ingest_time: datetime
    account_id: str | None = None
    cluster: str | None = None
    namespace: str | None = None
    resource_id: str | None = None
    identity_id: str | None = None
    event_type: str
    title: str
    severity: SeverityInfo
    keys: CorrelationKeys = CorrelationKeys()
    raw_evidence_uri: str
    checksum: str
    ocsf: dict[str, Any]


# --------------------------------------------------------------------------------------
# AI investigation contract. The model can only emit this structure; every fact must cite
# evidence and every containment option comes from a closed action vocabulary.
# --------------------------------------------------------------------------------------

ActionType = Literal["k8s.pod.quarantine_label", "notify.slack", "case.escalate"]


class Fact(BaseModel):
    statement: str
    evidence_ids: list[str] = Field(min_length=1)


class Hypothesis(BaseModel):
    statement: str
    confidence: Literal["low", "medium", "high"]
    supporting_evidence: list[str]
    contradicting_evidence: list[str] = []


class ContainmentOption(BaseModel):
    action_type: ActionType
    target_entity_id: str
    rationale: str
    expected_blast_radius: str
    prerequisites: list[str] = []


class Investigation(BaseModel):
    synopsis: str = Field(max_length=600)
    observed_facts: list[Fact]
    hypotheses: list[Hypothesis]
    missing_evidence: list[str]
    containment_options: list[ContainmentOption]
    confidence_limits: str


# --------------------------------------------------------------------------------------
# Response contract
# --------------------------------------------------------------------------------------


class ActionClass(StrEnum):
    READ_ONLY = "read_only"
    NOTIFICATION = "notification"
    REVERSIBLE_TEST = "reversible_test"
    DISRUPTIVE = "disruptive"
    IRREVERSIBLE = "irreversible"


class Target(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str
    name: str
    uid: str
    cluster: str | None = None
    namespace: str | None = None
    labels: dict[str, str] = {}


class ResponseProposal(BaseModel):
    proposal_id: str
    case_id: str
    action_type: str
    target: Target
    environment: str
    parameters: dict[str, Any] = {}
    rationale: str
    requested_by: str
    created_at: datetime
    dry_run_passed: bool | None = None
    impact_preview: dict[str, Any] = {}
