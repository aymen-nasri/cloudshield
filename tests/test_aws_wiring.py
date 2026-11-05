"""Configuring the AWS paths, and the findings worker's loop. The emulator job runs the real thing."""

import threading

import pytest

from core.app import Settings, build_evidence
from ingestion.adapters import PayloadError
from ingestion.evidence import InMemoryEvidenceStore, LocalEvidenceStore
from ingestion.pipeline import IngestResult
from ingestion.sqs_consumer import SqsConsumer


@pytest.mark.parametrize(
    "half", [{"evidence_bucket": "b"}, {"evidence_kms_key_id": "k"}], ids=["bucket-only", "key-only"]
)
def test_half_an_s3_configuration_stops_startup(half):
    with pytest.raises(ValueError, match="needs both"):
        build_evidence(Settings(**half))


def test_a_bucket_and_a_directory_together_stop_startup(tmp_path):
    settings = Settings(evidence_bucket="b", evidence_kms_key_id="k", evidence_dir=tmp_path)
    with pytest.raises(ValueError, match="not both"):
        build_evidence(settings)


def test_with_no_bucket_evidence_stays_local(tmp_path):
    assert isinstance(build_evidence(Settings()), InMemoryEvidenceStore)
    assert isinstance(build_evidence(Settings(evidence_dir=tmp_path)), LocalEvidenceStore)


class FakeSqs:
    """Hands out each batch once, then blocks the worker's loop by stopping it."""

    def __init__(self, batches, stop) -> None:
        self.batches = list(batches)
        self.stop = stop
        self.deleted = []

    def receive_message(self, **_):
        if not self.batches:
            self.stop.set()
            return {}
        batch = self.batches.pop(0)
        if isinstance(batch, Exception):
            raise batch
        return {"Messages": batch}

    def delete_message(self, QueueUrl, ReceiptHandle):  # noqa: N803
        self.deleted.append(ReceiptHandle)


class FakePipeline:
    def ingest(self, raw, adapter):
        if raw == b"bad":
            raise PayloadError("bad")
        return IngestResult("duplicate" if raw == b"again" else "accepted", "key")


def _message(body: str) -> dict:
    return {"MessageId": body, "ReceiptHandle": body, "Body": body}


def test_the_worker_survives_a_failed_poll_and_reports_each_result():
    stop = threading.Event()
    client = FakeSqs([ConnectionError("network"), [_message("ok"), _message("again"), _message("bad")]], stop)
    results: list[str] = []
    consumer = SqsConsumer("queue", FakePipeline(), None, client=client, on_result=results.append)

    consumer.run(stop, wait_seconds=0, retry_seconds=0)

    assert results == ["accepted", "duplicate", "invalid"]
    assert client.deleted == ["ok", "again"]  # a bad message stays, for the dead-letter queue


def test_the_worker_stops_when_told():
    stop = threading.Event()
    stop.set()
    client = FakeSqs([[_message("ok")]], stop)
    SqsConsumer("queue", FakePipeline(), None, client=client).run(stop)
    assert client.deleted == []
