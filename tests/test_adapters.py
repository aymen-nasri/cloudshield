import json

import pytest

from common.models import Severity
from common.timeutil import parse_time
from ingestion.adapters import PayloadError, WazuhAdapter
from tests.conftest import ACCOUNT, CLUSTER, NOW, fixture_bytes


def _event(adapter, raw: bytes):
    payload = adapter.parse(raw)
    return adapter.to_event(
        payload, event_id="evt_x", ingest_time=NOW, raw_uri="mem://x", checksum="sha256:x"
    )


def test_falco_alert_is_normalized_with_pod_context(falco):
    event = _event(falco, fixture_bytes("s1_suspicious_process", "falco_alert.json"))

    assert event.source == "falco"
    assert event.source_event_id == "6f1c2a9e-4b7d-4d1e-9a51-2c0e7f3b8a10"
    assert event.resource_id == "k8s:pod/shop/checkout-7d9f6c-x2k8p"
    assert (event.cluster, event.account_id) == (CLUSTER, ACCOUNT)
    assert event.keys.pod_uid == "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
    assert event.severity.normalized is Severity.MEDIUM
    assert event.severity.original == "Warning"
    assert event.event_type == "process.unexpected_execution"
    assert event.ocsf["class_uid"] == 2004
    assert event.ocsf["attacks"][0]["technique"]["uid"] == "T1059"
    assert event.ocsf["attacks"][0]["tactic"]["uid"] == "TA0002"


def test_falco_nanosecond_timestamps_are_parsed(falco):
    event = _event(falco, fixture_bytes("s1_suspicious_process", "falco_alert.json"))
    assert event.event_time.isoformat() == "2026-10-28T14:02:40.512345+00:00"


def test_guardduty_finding_maps_pod_uid_and_scope(guardduty):
    event = _event(guardduty, fixture_bytes("s1_suspicious_process", "guardduty_finding.json"))

    assert event.cluster == CLUSTER
    assert event.account_id == ACCOUNT
    assert event.keys.pod_uid == "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
    assert event.keys.instance_id == "i-0a1b2c3d4e5f60718"
    assert event.event_type == "guardduty.Execution:Runtime/NewBinaryExecuted"
    assert event.severity.normalized is Severity.MEDIUM


@pytest.mark.parametrize(
    "score, expected",
    [(2.0, Severity.LOW), (5.0, Severity.MEDIUM), (8.0, Severity.HIGH), (9.5, Severity.CRITICAL)],
)
def test_guardduty_severity_bands(guardduty, score, expected):
    raw = json.loads(fixture_bytes("s1_suspicious_process", "guardduty_finding.json"))
    raw["detail"]["severity"] = score
    assert _event(guardduty, json.dumps(raw).encode()).severity.normalized is expected


def test_wazuh_alert_uses_agent_instance_label():
    raw = json.dumps(
        {
            "id": "1730124300.88412",
            "timestamp": "2026-10-28T14:05:00.000+0000",
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "sshd: brute force trying to get access",
                "mitre": {"id": ["T1110"]},
            },
            "agent": {"id": "003", "name": "web-01", "labels": {"aws.instance_id": "i-0f1e2d3c4b5a69788"}},
        }
    ).encode()
    event = _event(WazuhAdapter(account_id=ACCOUNT), raw)
    assert event.keys.instance_id == "i-0f1e2d3c4b5a69788"
    assert event.severity.normalized is Severity.MEDIUM
    assert event.event_time == parse_time("2026-10-28T14:05:00Z")


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[1, 2]", b'{"rule": "x"}', b"{" + b" " * 300_000 + b"}"],
    ids=["not-json", "not-object", "missing-fields", "oversized"],
)
def test_malformed_payloads_are_rejected(falco, raw):
    with pytest.raises(PayloadError):
        falco.parse(raw)
