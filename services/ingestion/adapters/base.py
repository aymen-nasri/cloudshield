"""Adapter contract shared by every signal source."""

import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from common.models import NormalizedEvent

MAX_PAYLOAD_BYTES = 256 * 1024

# MITRE ATT&CK tactic tags as Falco and Wazuh rules write them.
TACTICS: dict[str, tuple[str, str]] = {
    "mitre_initial_access": ("TA0001", "Initial Access"),
    "mitre_execution": ("TA0002", "Execution"),
    "mitre_persistence": ("TA0003", "Persistence"),
    "mitre_privilege_escalation": ("TA0004", "Privilege Escalation"),
    "mitre_defense_evasion": ("TA0005", "Defense Evasion"),
    "mitre_credential_access": ("TA0006", "Credential Access"),
    "mitre_discovery": ("TA0007", "Discovery"),
    "mitre_lateral_movement": ("TA0008", "Lateral Movement"),
    "mitre_command_and_control": ("TA0011", "Command and Control"),
    "mitre_exfiltration": ("TA0010", "Exfiltration"),
}


class PayloadError(ValueError):
    """The payload is malformed, oversized or missing required fields."""


class SourceAdapter(Protocol):
    name: str

    def parse(self, raw: bytes) -> dict[str, Any]: ...

    def source_event_id(self, payload: dict[str, Any]) -> str: ...

    def to_event(
        self,
        payload: dict[str, Any],
        *,
        event_id: str,
        ingest_time: datetime,
        raw_uri: str,
        checksum: str,
    ) -> NormalizedEvent: ...


def dedup_key(source: str, source_event_id: str) -> str:
    return hashlib.sha256(f"{source}:{source_event_id}".encode()).hexdigest()


def load_json_object(raw: bytes, required: tuple[str, ...]) -> dict[str, Any]:
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise PayloadError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayloadError(f"invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PayloadError("payload must be a JSON object")
    missing = [key for key in required if key not in payload]
    if missing:
        raise PayloadError(f"missing required fields: {', '.join(missing)}")
    return payload


def attacks_from_tags(tags: list[str]) -> list[dict[str, Any]]:
    """Turn rule tags such as ["mitre_execution", "T1059"] into OCSF `attacks` entries."""
    tactic = next((TACTICS[t] for t in tags if t in TACTICS), None)
    attacks = []
    for tag in tags:
        if tag.startswith("T") and tag[1:].replace(".", "").isdigit():
            entry: dict[str, Any] = {"technique": {"uid": tag}}
            if tactic:
                entry["tactic"] = {"uid": tactic[0], "name": tactic[1]}
            attacks.append(entry)
    return attacks
