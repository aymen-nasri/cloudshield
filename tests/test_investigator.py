"""Investigator guarantees: redaction, untrusted-data framing, citation enforcement (T-06)."""

import json

import pytest

from investigator.bundle import build_bundle, redact, render_untrusted
from investigator.service import Investigator
from investigator.validate import InvestigationRejected, parse_and_validate
from tests.conftest import fixture_bytes


@pytest.fixture
def s1_bundle(pipeline, falco, guardduty, cases):
    pipeline.ingest(fixture_bytes("s1_suspicious_process", "falco_alert.json"), falco)
    pipeline.ingest(fixture_bytes("s1_suspicious_process", "guardduty_finding.json"), guardduty)
    bundle = build_bundle(cases.list()[0])
    bundle.entities = [{"entity_id": "k8s:pod/shop/checkout-7d9f6c-x2k8p", "kind": "pod"}]
    return bundle


def _answer(
    bundle,
    *,
    evidence_ids=None,
    target="k8s:pod/shop/checkout-7d9f6c-x2k8p",
    action="k8s.pod.quarantine_label",
):
    first = sorted(bundle.event_ids)[0]
    return json.dumps(
        {
            "synopsis": "Remote script piped to shell in checkout.",
            "observed_facts": [{"statement": "curl | sh ran", "evidence_ids": evidence_ids or [first]}],
            "hypotheses": [],
            "missing_evidence": ["flow logs"],
            "containment_options": [
                {
                    "action_type": action,
                    "target_entity_id": target,
                    "rationale": "contain",
                    "expected_blast_radius": "one replica",
                    "prerequisites": [],
                }
            ],
            "confidence_limits": "payload unknown",
        }
    )


class ScriptedModel:
    model_id = "scripted"

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        self.prompts.append(user)
        return self.answers.pop(0)


def test_secrets_are_redacted():
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE password=hunter2"
    cleaned = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
    assert "hunter2" not in cleaned


def test_valid_cited_answer_is_accepted(s1_bundle):
    inv = parse_and_validate(_answer(s1_bundle), s1_bundle)
    assert inv.containment_options[0].action_type == "k8s.pod.quarantine_label"


def test_answer_in_markdown_fence_is_accepted(s1_bundle):
    assert parse_and_validate(f"```json\n{_answer(s1_bundle)}\n```", s1_bundle)


@pytest.mark.parametrize(
    "kwargs, problem",
    [
        ({"evidence_ids": ["evt_INVENTED"]}, "unknown evidence"),
        ({"target": "k8s:pod/kube-system/coredns"}, "unknown entity"),
        ({"action": "shell.exec"}, "schema"),
    ],
)
def test_ungrounded_or_unsafe_answers_are_rejected(s1_bundle, kwargs, problem):
    with pytest.raises(InvestigationRejected) as exc:
        parse_and_validate(_answer(s1_bundle, **kwargs), s1_bundle)
    assert problem in str(exc.value)


def test_uncited_fact_is_rejected(s1_bundle):
    answer = json.loads(_answer(s1_bundle))
    answer["observed_facts"][0]["evidence_ids"] = []
    with pytest.raises(InvestigationRejected):
        parse_and_validate(json.dumps(answer), s1_bundle)


def test_t06_injected_instructions_stay_inside_the_untrusted_block(pipeline, falco, cases):
    pipeline.ingest(fixture_bytes("s8_prompt_injection", "falco_alert.json"), falco)
    rendered = render_untrusted(build_bundle(cases.list()[0]))

    start = rendered.index("<untrusted_evidence")
    end = rendered.index("</untrusted_evidence")
    injected = rendered.index("ignore all previous instructions")
    assert start < injected < end


def test_investigator_retries_once_with_validator_feedback_only(s1_bundle):
    model = ScriptedModel(_answer(s1_bundle, evidence_ids=["evt_INVENTED"]), _answer(s1_bundle))
    run = Investigator(model).investigate(s1_bundle)

    assert run.attempts == 2
    assert "unknown evidence" in model.prompts[1]


def test_investigator_gives_up_after_max_attempts(s1_bundle):
    bad = _answer(s1_bundle, evidence_ids=["evt_INVENTED"])
    with pytest.raises(InvestigationRejected):
        Investigator(ScriptedModel(bad, bad)).investigate(s1_bundle)
