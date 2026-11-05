"""Every API route needs a login. New routes are covered automatically, through the OpenAPI schema."""

import pytest
from fastapi.testclient import TestClient

from core.app import Settings, create_app
from core.auth import AnalystDirectory, Principal
from ingestion.auth import SourceCredential
from tests.conftest import fixture_bytes

VIEWER = {"authorization": "Bearer vic-test"}
PUBLIC = {("get", "/healthz")}  # says nothing about any incident; kubelet probes can't log in


def _client() -> TestClient:
    settings = Settings(
        cluster="cs-lab-eks",
        credentials={"falco": SourceCredential(token="falco-test")},
        analysts=AnalystDirectory.from_tokens({"vic-test": Principal("analyst:vic", frozenset({"viewer"}))}),
    )
    return TestClient(create_app(settings))


def _routes() -> list[tuple[str, str]]:
    paths = _client().app.openapi()["paths"]
    return sorted((method, path) for path, item in paths.items() for method in item)


@pytest.mark.parametrize(("method", "path"), _routes(), ids=lambda value: value)
def test_route_refuses_a_request_without_a_login(method, path):
    if (method, path) in PUBLIC:
        pytest.skip("public on purpose")
    url = path.replace("{source}", "falco")
    for name in ("case_id", "proposal_id", "investigation_id", "entity_id"):
        url = url.replace(f"{{{name}}}", "x")
    url = url.replace("{entity_id:path}", "x")
    assert _client().request(method.upper(), url).status_code == 401


def test_the_sweep_covers_the_routes_that_were_open():
    routes = {path for _, path in _routes()}
    assert {"/v1/cases", "/v1/cases/{case_id}", "/v1/audit", "/v1/health/coverage"} <= routes
    assert any(path.endswith("/graph") for path in routes)


def test_a_viewer_can_read_and_nobody_else_can():
    client = _client()
    alert = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    client.post("/v1/ingest/falco", content=alert, headers={"authorization": "Bearer falco-test"})

    [case] = client.get("/v1/cases", headers=VIEWER).json()
    wrong = {"authorization": "Bearer not-a-token"}
    for url in ("/v1/cases", f"/v1/cases/{case['case_id']}", "/v1/audit", "/v1/health/coverage"):
        assert client.get(url, headers=VIEWER).status_code == 200, url
        assert client.get(url, headers=wrong).status_code == 401, url
        assert "curl" not in client.get(url).text, url
