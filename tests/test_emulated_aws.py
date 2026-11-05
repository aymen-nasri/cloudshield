"""The AWS paths against Moto, using the resources the lab's real OpenTofu files created.

Run by scripts/emulated_aws.sh. An emulator imitates AWS's APIs: this shows our requests, resource
wiring and message handling hold together. It doesn't show that real AWS behaves the same, and it
doesn't enforce IAM. Moto has no EKS Pod Identity, so that lookup isn't tested here.
"""

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

boto3 = pytest.importorskip("boto3")

from fastapi.testclient import TestClient  # noqa: E402

from cases.store import InMemoryCaseStore  # noqa: E402
from core.app import Settings, create_app  # noqa: E402
from core.auth import AnalystDirectory, Principal  # noqa: E402
from correlation.engine import CorrelationEngine  # noqa: E402
from enrichment.context import instance_for_node  # noqa: E402
from ingestion.adapters import GuardDutyAdapter  # noqa: E402
from ingestion.evidence import InMemoryEvidenceStore, S3EvidenceStore  # noqa: E402
from ingestion.pipeline import IngestPipeline, InMemoryEventStore  # noqa: E402
from ingestion.sqs_consumer import SqsConsumer  # noqa: E402

ENDPOINT = os.getenv("CLOUDSHIELD_EMULATED_AWS")
pytestmark = pytest.mark.skipif(not ENDPOINT, reason="needs an AWS emulator: run scripts/emulated_aws.sh")

FIXTURE = Path(__file__).parents[1] / "detections/fixtures/s1_suspicious_process/guardduty_finding.json"
RULE = "cloudshield-guardduty-findings"


def _client(service: str):
    return boto3.client(service, endpoint_url=ENDPOINT, region_name="eu-west-1")


@pytest.fixture
def sqs():
    client = _client("sqs")
    for name in ("cloudshield-lab-findings", "cloudshield-lab-findings-dlq"):
        url = client.get_queue_url(QueueName=name)["QueueUrl"]
        # Not purge_queue: like AWS, the emulator allows one purge per queue every 60 seconds.
        while messages := client.receive_message(QueueUrl=url, MaxNumberOfMessages=10).get("Messages"):
            for message in messages:
                client.delete_message(QueueUrl=url, ReceiptHandle=message["ReceiptHandle"])
    return client


def _url(sqs, name: str = "cloudshield-lab-findings") -> str:
    return sqs.get_queue_url(QueueName=name)["QueueUrl"]


def _count(sqs, name: str = "cloudshield-lab-findings") -> int:
    attrs = sqs.get_queue_attributes(QueueUrl=_url(sqs, name), AttributeNames=["All"])["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])


def _consumer(sqs) -> tuple[SqsConsumer, InMemoryCaseStore, InMemoryEventStore]:
    cases, events = InMemoryCaseStore(), InMemoryEventStore()
    engine = CorrelationEngine(cases)
    pipeline = IngestPipeline(events, InMemoryEvidenceStore(), on_accepted=engine.correlate)
    return SqsConsumer(_url(sqs), pipeline, GuardDutyAdapter(), client=sqs), cases, events


def _publish(detail: dict, *, source: str = "aws.guardduty", detail_type: str = "GuardDuty Finding") -> None:
    response = _client("events").put_events(
        Entries=[{"Source": source, "DetailType": detail_type, "Detail": json.dumps(detail)}]
    )
    assert response["FailedEntryCount"] == 0


def _finding() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["detail"]


def _wait_for(check, seconds: float = 15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if result := check():
            return result
        time.sleep(0.2)
    raise AssertionError("it never happened")


def test_tofu_wired_the_rule_to_the_queue():
    events = _client("events")
    pattern = json.loads(events.describe_rule(Name=RULE)["EventPattern"])
    assert pattern == {"source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"]}
    [target] = events.list_targets_by_rule(Rule=RULE)["Targets"]
    assert target["Arn"].endswith(":cloudshield-lab-findings")


def test_tofu_gave_the_queue_a_dead_letter_queue_and_a_narrow_policy(sqs):
    attrs = sqs.get_queue_attributes(QueueUrl=_url(sqs), AttributeNames=["All"])["Attributes"]
    redrive = json.loads(attrs["RedrivePolicy"])
    assert redrive["maxReceiveCount"] == 5
    assert redrive["deadLetterTargetArn"].endswith(":cloudshield-lab-findings-dlq")
    [statement] = json.loads(attrs["Policy"])["Statement"]
    assert statement["Principal"] == {"Service": "events.amazonaws.com"}
    assert statement["Action"] == "sqs:SendMessage"


def test_a_finding_goes_through_eventbridge_and_sqs_into_a_case(sqs):
    _publish(_finding())
    consumer, cases, _ = _consumer(sqs)

    assert consumer.poll_once(wait_seconds=1) == 1

    [case] = cases.list()
    [event] = case.events
    assert event.source == "guardduty"
    assert event.source_event_id.startswith(_finding()["id"])
    assert event.account_id == _finding()["accountId"]
    assert _count(sqs) == 0  # deleted only after it was ingested


def test_the_same_finding_delivered_twice_is_one_event(sqs):
    _publish(_finding())
    _publish(_finding())
    consumer, cases, events = _consumer(sqs)

    assert consumer.poll_once(wait_seconds=1) == 2

    assert len(events.all()) == 1
    assert len(cases.list()) == 1
    assert _count(sqs) == 0


def test_events_the_rule_does_not_match_never_arrive(sqs):
    _publish(_finding(), source="aws.securityhub")
    _publish(_finding(), detail_type="Something Else")
    assert _count(sqs) == 0


def test_a_malformed_message_ends_up_in_the_dead_letter_queue(sqs):
    sqs.set_queue_attributes(QueueUrl=_url(sqs), Attributes={"VisibilityTimeout": "0"})
    try:
        sqs.send_message(QueueUrl=_url(sqs), MessageBody='{"not": "a finding"}')
        consumer, cases, _ = _consumer(sqs)
        for _ in range(7):
            assert consumer.poll_once(wait_seconds=0) == 0
        assert _count(sqs) == 0
        assert _count(sqs, "cloudshield-lab-findings-dlq") == 1
        assert cases.list() == []
    finally:
        sqs.set_queue_attributes(QueueUrl=_url(sqs), Attributes={"VisibilityTimeout": "60"})


@pytest.fixture
def evidence_bucket() -> str:
    names = [b["Name"] for b in _client("s3").list_buckets()["Buckets"]]
    return next(n for n in names if n.startswith("cloudshield-lab-evidence-"))


def test_tofu_configured_the_evidence_bucket(evidence_bucket):
    s3 = _client("s3")
    assert s3.get_bucket_versioning(Bucket=evidence_bucket)["Status"] == "Enabled"
    lock = s3.get_object_lock_configuration(Bucket=evidence_bucket)["ObjectLockConfiguration"]
    assert lock["ObjectLockEnabled"] == "Enabled"
    retention = lock["Rule"]["DefaultRetention"]
    assert (retention["Mode"], retention["Days"]) == ("GOVERNANCE", 7)
    rule = s3.get_bucket_encryption(Bucket=evidence_bucket)["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"
    block = s3.get_public_access_block(Bucket=evidence_bucket)["PublicAccessBlockConfiguration"]
    assert all(block.values())


def test_evidence_is_archived_with_its_checksum_and_encryption(evidence_bucket):
    s3, raw = _client("s3"), FIXTURE.read_bytes()
    key_id = _client("kms").list_keys()["Keys"][0]["KeyId"]
    store = S3EvidenceStore(evidence_bucket, key_id, client=s3)

    uri, checksum = store.archive("guardduty", raw, datetime(2026, 11, 5, tzinfo=UTC))

    assert uri.startswith(f"s3://{evidence_bucket}/") and checksum.startswith("sha256:")
    stored = s3.get_object(Bucket=evidence_bucket, Key=uri.split("/", 3)[3], ChecksumMode="ENABLED")
    assert stored["Body"].read() == raw
    assert stored["ServerSideEncryption"] == "aws:kms"
    assert stored["VersionId"]


def test_locked_evidence_cannot_be_deleted(evidence_bucket):
    s3, raw = _client("s3"), b'{"evidence": "locked"}'
    key_id = _client("kms").list_keys()["Keys"][0]["KeyId"]
    uri, _ = S3EvidenceStore(evidence_bucket, key_id, client=s3).archive(
        "guardduty", raw, datetime(2026, 11, 5, tzinfo=UTC)
    )
    key = uri.split("/", 3)[3]
    version = s3.head_object(Bucket=evidence_bucket, Key=key)["VersionId"]
    with pytest.raises(s3.exceptions.ClientError, match="AccessDenied"):
        s3.delete_object(Bucket=evidence_bucket, Key=key, VersionId=version)


def test_a_node_name_resolves_to_its_instance():
    ec2 = _client("ec2")
    image = ec2.describe_images()["Images"][0]["ImageId"]
    [instance] = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1)["Instances"]
    assert instance_for_node(ec2, instance["PrivateDnsName"]) == instance["InstanceId"]
    assert instance_for_node(ec2, "no-such-node.internal") is None


def test_the_running_app_reads_the_queue_and_keeps_evidence_in_the_bucket(sqs, evidence_bucket, monkeypatch):
    """The whole path in the app itself, configured as a deployment would be.

    Last in this file, because its bad message stays on the queue until its visibility timeout ends.
    """
    monkeypatch.setenv("AWS_ENDPOINT_URL", ENDPOINT)
    settings = Settings(
        region="eu-west-1",
        evidence_bucket=evidence_bucket,
        evidence_kms_key_id=_client("kms").list_keys()["Keys"][0]["KeyId"],
        findings_queue_url=_url(sqs),
        findings_wait_seconds=1,
        analysts=AnalystDirectory.from_tokens({"reader": Principal("analyst:r", frozenset({"viewer"}))}),
    )
    reader = {"authorization": "Bearer reader"}
    sqs.send_message(QueueUrl=_url(sqs), MessageBody="not json")  # a bad message must not stop the worker
    _publish(_finding())

    with TestClient(create_app(settings)) as client:
        [summary] = _wait_for(lambda: client.get("/v1/cases", headers=reader).json())
        case = client.get(f"/v1/cases/{summary['case_id']}", headers=reader).json()
        coverage = client.get("/v1/health/coverage", headers=reader).json()
        # The worker counts a message just after handling it, so this can be a moment behind the case.
        metrics = _wait_for(
            lambda: (
                (text := client.get("/metrics", headers=reader).text)
                if 'result="accepted",source="guardduty"' in text
                else None
            )
        )

    [event] = case["events"]
    assert event["source"] == "guardduty"
    uri = event["raw_evidence_uri"]
    assert uri.startswith(f"s3://{evidence_bucket}/")
    stored = _client("s3").get_object(Bucket=evidence_bucket, Key=uri.split("/", 3)[3])
    assert json.loads(stored["Body"].read())["detail"]["id"] == _finding()["id"]
    assert coverage["sources"]["guardduty"]["state"] == "ok"
    assert 'result="invalid",source="guardduty"' in metrics
