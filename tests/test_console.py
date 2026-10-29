"""The analyst console: served safely, renders untrusted text safely, knows who is signed in."""

import re
from pathlib import Path

from fastapi.testclient import TestClient

from core.app import Settings, create_app
from core.auth import AnalystDirectory, Principal

STATIC = Path(__file__).resolve().parents[1] / "services" / "console" / "static"
BOB = {"authorization": "Bearer bob-test"}


def _client(demo_token: str | None = None) -> TestClient:
    settings = Settings(
        analysts=AnalystDirectory.from_tokens(
            {"bob-test": Principal("analyst:bob", frozenset({"incident-responder"}))}
        ),
        console_demo_token=demo_token,
    )
    return TestClient(create_app(settings))


def test_page_and_assets_ship_with_a_strict_content_security_policy():
    client = _client()
    for path, kind in [
        ("/console", "text/html"),
        ("/console/app.js", "text/javascript"),
        ("/console/style.css", "text/css"),
    ]:
        r = client.get(path)
        assert r.status_code == 200, path
        assert r.headers["content-type"].startswith(kind)
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert r.headers["x-content-type-options"] == "nosniff"


def test_only_known_assets_are_served():
    client = _client()
    assert client.get("/console/router.py").status_code == 404
    assert client.get("/console/..%2Frouter.py").status_code == 404


def test_untrusted_text_is_never_rendered_as_html():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js, sink
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script>(?!</script>)", html)  # no inline script: the CSP would block it anyway
    assert " style=" not in html


def test_me_reports_the_signed_in_analyst():
    client = _client()
    assert client.get("/v1/me").status_code == 401
    assert client.get("/v1/me", headers=BOB).json() == {"id": "analyst:bob", "roles": ["incident-responder"]}


def test_demo_session_exists_only_when_configured():
    assert _client().get("/v1/console/demo-session").status_code == 404
    assert _client(demo_token="bob-test").get("/v1/console/demo-session").json() == {"token": "bob-test"}


def test_console_demo_preloads_a_proposal_awaiting_approval():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "console_demo", Path(__file__).resolve().parents[1] / "scripts" / "console_demo.py"
    )
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    app = demo.build()
    demo.preload(app)

    client = TestClient(app)
    bob = {"authorization": f"Bearer {demo.BOB}"}
    s1 = next(c for c in client.get("/v1/cases").json() if c["event_count"] == 2)["case_id"]
    [proposal] = client.get(f"/v1/cases/{s1}/proposals", headers=bob).json()
    assert proposal["state"] == "awaiting_approval"
    assert (
        client.get(f"/v1/cases/{s1}/investigations", headers=bob).json()[0]["review_status"] == "unreviewed"
    )
