"""An Executor that asks the responder service to act, so this process holds no write access."""

from typing import Any

import httpx

from common.models import ResponseProposal, Target
from responder.quarantine import ExecutionResult, VerificationReport

# Verification retries while the CNI applies the label, so a call can take a while.
TIMEOUT_SECONDS = 90.0


class ResponderError(Exception):
    """The responder refused the request or could not be reached."""


class RemoteExecutor:
    identity = "cloudshield-responder"

    def __init__(self, client: httpx.Client, token: str) -> None:
        self.client = client
        self.headers = {"authorization": f"Bearer {token}"}

    @classmethod
    def connect(cls, url: str, token: str) -> "RemoteExecutor":
        return cls(httpx.Client(base_url=url, timeout=TIMEOUT_SECONDS), token)

    def _call(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.client.post(f"/v1/responder/{path}", json=body, headers=self.headers)
        except httpx.HTTPError as exc:
            raise ResponderError(f"responder unreachable: {exc}") from exc
        if response.status_code != 200:
            raise ResponderError(f"responder answered {response.status_code}: {response.text[:200]}")
        return response.json()

    def _proposal(self, path: str, proposal: ResponseProposal) -> dict[str, Any]:
        return self._call(path, proposal.model_dump(mode="json"))

    def current_labels(self, target: Target) -> dict[str, str] | None:
        return self._call("labels", {"target": target.model_dump(mode="json")})["labels"]

    def is_fresh(self, target: Target) -> bool:
        return self.current_labels(target) is not None

    def dry_run(self, proposal: ResponseProposal) -> tuple[ExecutionResult, dict[str, Any]]:
        answer = self._proposal("dry-run", proposal)
        return ExecutionResult(**answer["result"]), answer["impact"]

    def execute(self, proposal: ResponseProposal) -> ExecutionResult:
        return ExecutionResult(**self._proposal("execute", proposal)["result"])

    def verify(self, proposal: ResponseProposal) -> VerificationReport:
        return VerificationReport(**self._proposal("verify", proposal))
