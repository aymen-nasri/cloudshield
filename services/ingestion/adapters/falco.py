"""Falco alerts as delivered by Falcosidekick's webhook output."""

import hashlib
from datetime import datetime
from typing import Any

from common.models import (
    OCSF_SEVERITY_ID,
    CorrelationKeys,
    NormalizedEvent,
    Severity,
    SeverityInfo,
)
from common.timeutil import parse_time
from ingestion.adapters.base import PayloadError, attacks_from_tags, load_json_object

PRIORITY_MAP: dict[str, Severity] = {
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "notice": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "debug": Severity.INFORMATIONAL,
}

# Event types for CloudShield's own rules (detections/falco/cloudshield_rules.yaml).
RULE_EVENT_TYPES: dict[str, str] = {
    "Unexpected Process in Protected Workload": "process.unexpected_execution",
    "Remote Script Piped to Shell in Container": "process.remote_script_execution",
    "Kubectl Exec Shell in Protected Workload": "process.interactive_shell",
}


class FalcoAdapter:
    name = "falco"

    def __init__(self, *, cluster: str | None, account_id: str | None) -> None:
        # Falco runs inside one cluster, so scope comes from deployment config, not the alert.
        self.cluster = cluster
        self.account_id = account_id

    def parse(self, raw: bytes) -> dict[str, Any]:
        payload = load_json_object(raw, ("rule", "time", "priority", "output_fields"))
        if not isinstance(payload["output_fields"], dict):
            raise PayloadError("output_fields must be an object")
        return payload

    def source_event_id(self, payload: dict[str, Any]) -> str:
        if payload.get("uuid"):
            return str(payload["uuid"])
        # Older Falcosidekick versions send no uuid: derive a stable one from identifying fields.
        fields = payload["output_fields"]
        basis = "|".join(
            str(x)
            for x in (payload["rule"], payload["time"], payload.get("hostname"), fields.get("container.id"))
        )
        return "derived-" + hashlib.sha256(basis.encode()).hexdigest()[:32]

    def to_event(
        self,
        payload: dict[str, Any],
        *,
        event_id: str,
        ingest_time: datetime,
        raw_uri: str,
        checksum: str,
    ) -> NormalizedEvent:
        fields: dict[str, Any] = payload["output_fields"]
        event_time = parse_time(payload["time"])
        severity = PRIORITY_MAP.get(str(payload["priority"]).lower(), Severity.MEDIUM)
        namespace = fields.get("k8s.ns.name")
        pod = fields.get("k8s.pod.name")
        source_id = self.source_event_id(payload)

        return NormalizedEvent(
            event_id=event_id,
            source="falco",
            source_event_id=source_id,
            event_time=event_time,
            ingest_time=ingest_time,
            account_id=self.account_id,
            cluster=self.cluster,
            namespace=namespace,
            resource_id=f"k8s:pod/{namespace}/{pod}" if namespace and pod else None,
            identity_id=None,  # resolved later by enrichment (pod -> service account)
            event_type=RULE_EVENT_TYPES.get(payload["rule"], "runtime.detection"),
            title=payload["rule"],
            severity=SeverityInfo(normalized=severity, original=str(payload["priority"])),
            keys=CorrelationKeys(pod_uid=fields.get("k8s.pod.uid")),
            raw_evidence_uri=raw_uri,
            checksum=checksum,
            ocsf={
                "class_uid": 2004,
                "class_name": "Detection Finding",
                "category_uid": 2,
                "activity_id": 1,
                "severity_id": OCSF_SEVERITY_ID[severity],
                "time": int(event_time.timestamp() * 1000),
                "finding_info": {"uid": source_id, "title": payload["rule"]},
                "attacks": attacks_from_tags(list(payload.get("tags") or [])),
                "metadata": {
                    "version": "1.3.0",
                    "product": {"name": "Falco", "vendor_name": "Falco Project"},
                },
                "unmapped": {
                    "proc.name": fields.get("proc.name"),
                    "proc.cmdline": fields.get("proc.cmdline"),
                    "container.id": fields.get("container.id"),
                    "container.image.repository": fields.get("container.image.repository"),
                    "hostname": payload.get("hostname"),
                },
            },
        )
