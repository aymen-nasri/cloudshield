"""Worker that drains GuardDuty findings from SQS (EventBridge -> SQS -> here).

Messages are deleted only after successful ingestion. Failures are left on the queue so SQS
redelivers them; after maxReceiveCount the redrive policy moves them to the dead-letter queue.
"""

import logging
import threading
from collections.abc import Callable
from typing import Any

from ingestion.adapters import PayloadError, SourceAdapter
from ingestion.pipeline import IngestPipeline

log = logging.getLogger(__name__)


class SqsConsumer:
    def __init__(
        self,
        queue_url: str,
        pipeline: IngestPipeline,
        adapter: SourceAdapter,
        client: Any | None = None,
        *,
        on_result: Callable[[str], None] | None = None,
    ) -> None:
        if client is None:
            import boto3

            client = boto3.client("sqs")
        self.client = client
        self.queue_url = queue_url
        self.pipeline = pipeline
        self.adapter = adapter
        self.on_result = on_result  # told "accepted", "duplicate" or "invalid" for each message

    def poll_once(self, max_messages: int = 10, wait_seconds: int = 20) -> int:
        response = self.client.receive_message(
            QueueUrl=self.queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_seconds
        )
        handled = 0
        for message in response.get("Messages", []):
            try:
                result = self.pipeline.ingest(message["Body"].encode(), self.adapter)
            except PayloadError:
                # Malformed input will never succeed; let the redrive policy dead-letter it.
                log.warning("rejected malformed message %s", message["MessageId"])
                self._report("invalid")
                continue
            except Exception:
                log.exception("transient failure on %s; leaving for redelivery", message["MessageId"])
                continue
            self.client.delete_message(QueueUrl=self.queue_url, ReceiptHandle=message["ReceiptHandle"])
            self._report(result.status)
            handled += 1
        return handled

    def _report(self, result: str) -> None:
        if self.on_result:
            self.on_result(result)

    def run(self, stop: threading.Event, *, wait_seconds: int = 20, retry_seconds: float = 5) -> None:
        """Poll until told to stop. A failed poll, such as a network error, must not end the worker."""
        while not stop.is_set():
            try:
                self.poll_once(wait_seconds=wait_seconds)
            except Exception:
                log.exception("could not poll %s; trying again", self.queue_url)
                stop.wait(retry_seconds)
