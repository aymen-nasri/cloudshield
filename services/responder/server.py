"""The responder as its own process: the only place holding an identity that can change the cluster.

The CloudShield API calls it through responder.remote.RemoteExecutor and holds no Kubernetes write
access itself. The server doesn't trust that caller blindly: it needs a shared token, and it re-checks
the policy, so even a stolen token can only ask for allowlisted actions in allowlisted namespaces.

It can't check that a person approved: that lives in the API's database. So a stolen token could
still quarantine or release an allowlisted pod, but it could not touch anything else.
"""

import hmac
import os
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from common.models import ResponseProposal, Target
from core.app import Settings, build_traffic_probe
from policy.engine import ActionPolicy, Decision, PolicyEngine, load_policies
from responder.executor import Executor, KubernetesExecutor, UnsupportedAction
from responder.quarantine import KubernetesPodApi


class TargetRequest(BaseModel):
    target: Target


def build_app(
    executor: Executor,
    token: str,
    *,
    environment: str = "lab",
    policies: dict[str, ActionPolicy] | None = None,
) -> FastAPI:
    if not token:
        raise ValueError("the responder needs a token: refusing to run with none")
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
    def execute(proposal: ResponseProposal) -> dict[str, Any]:
        return {"result": asdict(run(lambda: executor.execute(allowed(proposal))))}

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
    return build_app(executor, token, environment=settings.environment)
