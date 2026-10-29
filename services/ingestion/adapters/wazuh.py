"""Wazuh alerts forwarded by the custom-cloudshield integration (infra/ansible/files)."""

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


def _severity(level: int) -> Severity:
    # Wazuh rule levels run 0-15.
    if level >= 14:
        return Severity.CRITICAL
    if level >= 11:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    if level >= 4:
        return Severity.LOW
    return Severity.INFORMATIONAL


def _instance_id(agent: dict[str, Any]) -> str | None:
    # The Ansible role labels each agent with its EC2 instance ID; Wazuh may nest or flatten it.
    labels = agent.get("labels") or {}
    return labels.get("aws.instance_id") or (labels.get("aws") or {}).get("instance_id")


class WazuhAdapter:
    name = "wazuh"

    def __init__(self, *, account_id: str | None) -> None:
        self.account_id = account_id

    def parse(self, raw: bytes) -> dict[str, Any]:
        payload = load_json_object(raw, ("id", "timestamp", "rule", "agent"))
        if "level" not in payload["rule"]:
            raise PayloadError("rule.level missing")
        return payload

    def source_event_id(self, payload: dict[str, Any]) -> str:
        return str(payload["id"])

    def to_event(
        self,
        payload: dict[str, Any],
        *,
        event_id: str,
        ingest_time: datetime,
        raw_uri: str,
        checksum: str,
    ) -> NormalizedEvent:
        rule: dict[str, Any] = payload["rule"]
        agent: dict[str, Any] = payload["agent"]
        level = int(rule["level"])
        severity = _severity(level)
        event_time = parse_time(payload["timestamp"])
        mitre = rule.get("mitre") or {}

        return NormalizedEvent(
            event_id=event_id,
            source="wazuh",
            source_event_id=self.source_event_id(payload),
            event_time=event_time,
            ingest_time=ingest_time,
            account_id=self.account_id,
            resource_id=f"host:{agent.get('name')}",
            event_type=f"host.wazuh_rule_{rule.get('id', 'unknown')}",
            title=rule.get("description", "Wazuh alert"),
            severity=SeverityInfo(normalized=severity, original=f"level {level}"),
            keys=CorrelationKeys(instance_id=_instance_id(agent)),
            raw_evidence_uri=raw_uri,
            checksum=checksum,
            ocsf={
                "class_uid": 2004,
                "class_name": "Detection Finding",
                "category_uid": 2,
                "activity_id": 1,
                "severity_id": OCSF_SEVERITY_ID[severity],
                "time": int(event_time.timestamp() * 1000),
                "finding_info": {"uid": str(payload["id"]), "title": rule.get("description")},
                "attacks": [{"technique": {"uid": t}} for t in mitre.get("id", [])],
                "device": {"name": agent.get("name"), "ip": agent.get("ip")},
                "metadata": {
                    "version": "1.3.0",
                    "product": {"name": "Wazuh", "vendor_name": "Wazuh"},
                },
                "unmapped": {
                    "full_log": payload.get("full_log"),
                    "srcip": (payload.get("data") or {}).get("srcip"),
                    "srcuser": (payload.get("data") or {}).get("srcuser"),
                    "syscheck.path": (payload.get("syscheck") or {}).get("path"),
                    "syscheck.event": (payload.get("syscheck") or {}).get("event"),
                },
            },
        )
