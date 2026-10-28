"""Amazon Bedrock client (Converse API), optionally with a Bedrock Guardrail attached."""

from typing import Any


class BedrockClient:
    def __init__(
        self,
        model_id: str,
        *,
        region: str | None = None,
        guardrail_id: str | None = None,
        guardrail_version: str | None = None,
        client: Any | None = None,
    ) -> None:
        if client is None:
            import boto3

            client = boto3.client("bedrock-runtime", region_name=region)
        self._client = client
        self.model_id = model_id
        self.guardrail = (guardrail_id, guardrail_version) if guardrail_id else None

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        request: dict[str, Any] = {
            "modelId": self.model_id,
            "system": [{"text": system}],
            "messages": [{"role": "user", "content": [{"text": user}]}],
            "inferenceConfig": {"maxTokens": max_tokens, "temperature": 0},
        }
        if self.guardrail:
            request["guardrailConfig"] = {
                "guardrailIdentifier": self.guardrail[0],
                "guardrailVersion": self.guardrail[1] or "DRAFT",
            }
        response = self._client.converse(**request)
        blocks = response["output"]["message"]["content"]
        return "".join(block.get("text", "") for block in blocks)
