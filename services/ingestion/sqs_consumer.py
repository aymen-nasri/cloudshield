"""Worker that drains GuardDuty/Security Hub findings from SQS (EventBridge -> SQS -> here).

Messages are deleted only after successful ingestion. Failures are left on the queue so SQS
redelivers them; after maxReceiveCount the redrive policy moves them to the dead-letter queue.
"""

import logging
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
    ) -> None:
        if client is None:
            import boto3

            client = boto3.client("sqs")
        self.client = client
        self.queue_url = queue_url
        self.pipeline = pipeline
        self.adapter = adapter

    def poll_once(self, max_messages: int = 10) -> int:
        response = self.client.receive_message(
            QueueUrl=self.queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=20
        )
        handled = 0
        for message in response.get("Messages", []):
            try:
                self.pipeline.ingest(message["Body"].encode(), self.adapter)
            except PayloadError:
                # Malformed input will never succeed; let the redrive policy dead-letter it.
                log.warning("rejected malformed message %s", message["MessageId"])
                continue
            except Exception:
                log.exception("transient failure on %s; leaving for redelivery", message["MessageId"])
                continue
            self.client.delete_message(QueueUrl=self.queue_url, ReceiptHandle=message["ReceiptHandle"])
            handled += 1
        return handled

    def run_forever(self) -> None:
        while True:
            self.poll_once()
