"""GuardDuty findings delivered as EventBridge events (via SQS)."""

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
from ingestion.adapters.base import PayloadError, load_json_object


def _severity(score: float) -> Severity:
    # GuardDuty bands: 1.0-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical.
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _dig(data: dict[str, Any], *path: str) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)  # type: ignore[assignment]
    return data


class GuardDutyAdapter:
    name = "guardduty"

    def parse(self, raw: bytes) -> dict[str, Any]:
        payload = load_json_object(raw, ("detail-type", "account", "detail"))
        if payload["detail-type"] != "GuardDuty Finding":
            raise PayloadError(f"unexpected detail-type {payload['detail-type']!r}")
        for key in ("id", "type", "severity", "updatedAt"):
            if key not in payload["detail"]:
                raise PayloadError(f"detail.{key} missing")
        return payload

    def source_event_id(self, payload: dict[str, Any]) -> str:
        # GuardDuty updates findings in place; each update is a distinct piece of evidence.
        detail = payload["detail"]
        return f"{detail['id']}:{detail['updatedAt']}"

    def to_event(
        self,
        payload: dict[str, Any],
        *,
        event_id: str,
        ingest_time: datetime,
        raw_uri: str,
        checksum: str,
    ) -> NormalizedEvent:
        detail: dict[str, Any] = payload["detail"]
        resource = detail.get("resource") or {}
        workload = _dig(resource, "kubernetesDetails", "kubernetesWorkloadDetails") or {}
        namespace = workload.get("namespace")
        pod_uid = workload.get("uid") if workload.get("type") == "pods" else None
        instance_id = _dig(resource, "instanceDetails", "instanceId")
        principal = _dig(resource, "accessKeyDetails", "principalId")
        event_time = parse_time(_dig(detail, "service", "eventLastSeen") or detail["updatedAt"])
        severity = _severity(float(detail["severity"]))

        if workload.get("name") and namespace:
            resource_id = f"k8s:{workload.get('type', 'workload')}/{namespace}/{workload['name']}"
        elif instance_id:
            resource_id = f"aws:ec2/{instance_id}"
        else:
            resource_id = None

        return NormalizedEvent(
            event_id=event_id,
            source="guardduty",
            source_event_id=self.source_event_id(payload),
            event_time=event_time,
            ingest_time=ingest_time,
            account_id=payload["account"],
            cluster=_dig(resource, "eksClusterDetails", "name"),
            namespace=namespace,
            resource_id=resource_id,
            identity_id=f"aws:principal/{principal}" if principal else None,
            event_type=f"guardduty.{detail['type']}",
            title=detail.get("title") or detail["type"],
            severity=SeverityInfo(normalized=severity, original=str(detail["severity"])),
            keys=CorrelationKeys(pod_uid=pod_uid, instance_id=instance_id),
            raw_evidence_uri=raw_uri,
            checksum=checksum,
            ocsf={
                "class_uid": 2004,
                "class_name": "Detection Finding",
                "category_uid": 2,
                "activity_id": 1,
                "severity_id": OCSF_SEVERITY_ID[severity],
                "time": int(event_time.timestamp() * 1000),
                "finding_info": {"uid": detail["id"], "title": detail.get("title"), "types": [detail["type"]]},
                "cloud": {"provider": "AWS", "account": {"uid": payload["account"]}, "region": payload.get("region")},
                "metadata": {
                    "version": "1.3.0",
                    "product": {"name": "GuardDuty", "vendor_name": "AWS"},
                },
            },
        )
