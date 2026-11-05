"""A model served by Ollama on your own machine: no account, no cost, and the evidence stays local."""

from typing import Any

import httpx

from common.models import Investigation


class OllamaClient:
    def __init__(
        self,
        model: str,
        *,
        url: str = "http://127.0.0.1:11434",
        timeout: float = 600.0,  # a small model on a CPU is slow, and this is a batch call
        client: httpx.Client | None = None,
    ) -> None:
        self._client = client or httpx.Client(timeout=timeout)
        self._url = url.rstrip("/")
        self._model = model
        self.model_id = f"ollama/{model}"

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        request: dict[str, Any] = {
            "model": self._model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            # Asks for the right shape. Whether the answer is true is still for parse_and_validate to check.
            "format": Investigation.model_json_schema(),
            # Ollama's default context can silently cut off a long evidence bundle.
            "options": {"temperature": 0, "seed": 42, "num_predict": max_tokens, "num_ctx": 8192},
        }
        response = self._client.post(f"{self._url}/api/chat", json=request)
        response.raise_for_status()
        return str(response.json()["message"]["content"])
