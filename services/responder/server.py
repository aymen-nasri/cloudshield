"""The responder as its own process: the only place holding an identity that can change the cluster.

The CloudShield API calls it through responder.remote.RemoteExecutor and holds no Kubernetes write
access itself. The server doesn't trust that caller: it needs a shared token, it re-checks the policy,
and it runs an action only with approvals signed by people whose public keys it holds. So a stolen
token and a stolen API pod can't start an action by themselves.
"""

import hmac
import os
import threading
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from common.models import ResponseProposal, Target
from common.timeutil import utcnow
from core.app import Settings, build_traffic_probe
from policy.engine import ActionPolicy, Decision, PolicyEngine, load_policies
from policy.signing import ApproverKey, SignedApproval, load_approver_keys, valid_approvers
from responder.executor import Executor, KubernetesExecutor, UnsupportedAction
from responder.quarantine import KubernetesPodApi


class TargetRequest(BaseModel):
    target: Target


class ExecuteRequest(BaseModel):
    proposal: ResponseProposal
    approvals: list[SignedApproval] = []


def build_app(
    executor: Executor,
    token: str,
    *,
    approver_keys: dict[str, ApproverKey],
    environment: str = "lab",
    policies: dict[str, ActionPolicy] | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> FastAPI:
    if not token:
        raise ValueError("the responder needs a token: refusing to run with none")
    if not approver_keys:
        raise ValueError("the responder needs approver keys: with none, nothing could ever be approved")
    allowlist = policies if policies is not None else load_policies()
    engine = PolicyEngine(allowlist, is_fresh=executor.is_fresh)

    def caller(authorization: Annotated[str | None, Header()] = None) -> None:
        # Compared as bytes: on str, compare_digest raises for non-ASCII, and a caller controls this header.
        if not authorization or not hmac.compare_digest(authorization.encode(), f"Bearer {token}".encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "caller not authenticated")

    def allowed(proposal: ResponseProposal) -> ResponseProposal:
        """The responder's own decision: what the caller says about the environment doesn't count."""
        if proposal.environment != environment:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"this responder only acts in {environment!r}")
        result = engine.evaluate(proposal)
        if result.decision is Decision.DENY:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "; ".join(result.reasons))
        return proposal

    executed: set[str] = set()  # in memory: after a restart, an approval's short TTL is what limits a replay
    executed_lock = threading.Lock()

    def approved(proposal: ResponseProposal, approvals: list[SignedApproval]) -> None:
        """The check that doesn't depend on the caller: enough people really signed this exact proposal."""
        # How many it takes comes from the pod's labels now, not the labels written in the proposal.
        live = executor.current_labels(proposal.target)
        current = proposal.target.model_copy(update={"labels": live or proposal.target.labels})
        policy = engine.evaluate(proposal.model_copy(update={"target": current}))
        valid = valid_approvers(proposal, approvals, approver_keys, policy, now=clock())
        if len(valid) < policy.required_approvals:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"{len(valid)} valid signed approval(s), {policy.required_approvals} required",
            )
        with executed_lock:
            if proposal.proposal_id in executed:
                raise HTTPException(status.HTTP_409_CONFLICT, "this proposal was already executed")
            executed.add(proposal.proposal_id)

    def run(step: Callable[[], Any]) -> Any:
        try:
            return step()
        except UnsupportedAction as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    app = FastAPI(title="CloudShield responder", docs_url=None, redoc_url=None, openapi_url=None)
    auth = [Depends(caller)]

    @app.post("/v1/responder/labels", dependencies=auth)
    def labels(body: TargetRequest) -> dict[str, Any]:
        return {"labels": executor.current_labels(body.target)}

    @app.post("/v1/responder/dry-run", dependencies=auth)
    def dry_run(proposal: ResponseProposal) -> dict[str, Any]:
        # This call is the dry run, so the policy's "dry run first" rule can't apply to it yet.
        checked = allowed(proposal.model_copy(update={"dry_run_passed": True}))
        result, impact = run(lambda: executor.dry_run(checked))
        return {"result": asdict(result), "impact": impact}

    @app.post("/v1/responder/execute", dependencies=auth)
    def execute(body: ExecuteRequest) -> dict[str, Any]:
        proposal = allowed(body.proposal)
        approved(proposal, body.approvals)
        return {"result": asdict(run(lambda: executor.execute(proposal)))}

    @app.post("/v1/responder/verify", dependencies=auth)
    def verify(proposal: ResponseProposal) -> dict[str, Any]:
        # Reads only, and must still answer after the target has gone: no freshness check here.
        return asdict(run(lambda: executor.verify(proposal)))

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def create_app() -> FastAPI:
    """Uvicorn's entry point in the pod: this pod's own service account is the responder identity."""
    settings = Settings.from_env()
    token_file = os.environ["CLOUDSHIELD_RESPONDER_API_TOKEN_FILE"]
    executor = KubernetesExecutor(KubernetesPodApi(), probe=build_traffic_probe(settings))
    token = Path(token_file).read_text(encoding="utf-8").strip()
    keys = load_approver_keys(Path(os.environ["CLOUDSHIELD_APPROVER_KEYS_FILE"]).read_text(encoding="utf-8"))
    return build_app(executor, token, approver_keys=keys, environment=settings.environment)
