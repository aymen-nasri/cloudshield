"""Our Bedrock calls against AWS's own published API model, using botocore's Stubber.

Stubber rejects a request or a response that doesn't fit the API definition shipped with boto3. No
call leaves the machine, so this says nothing about Bedrock's behavior: only that we speak its format.
"""

import json

import pytest

boto3 = pytest.importorskip("boto3")

from botocore.exceptions import ParamValidationError  # noqa: E402
from botocore.stub import Stubber  # noqa: E402

from investigator.bedrock import BedrockClient  # noqa: E402
from investigator.service import Investigator  # noqa: E402
from investigator.validate import InvestigationRejected  # noqa: E402
from tests.conftest import fixture_bytes  # noqa: E402

MODEL = "anthropic.claude-sonnet-4-5"


@pytest.fixture
def runtime():
    client = boto3.client(
        "bedrock-runtime", region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x"
    )
    with Stubber(client) as stub:
        yield client, stub
        stub.assert_no_pending_responses()


def _response(text: str, stop: str = "end_turn") -> dict:
    return {
        "output": {"message": {"role": "assistant", "content": [{"text": text}]}},
        "stopReason": stop,
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        "metrics": {"latencyMs": 1},
    }


def test_the_request_and_the_response_fit_the_api_definition(runtime):
    client, stub = runtime
    stub.add_response(
        "converse",
        _response("hello"),
        {
            "modelId": MODEL,
            "system": [{"text": "the rules"}],
            "messages": [{"role": "user", "content": [{"text": "the evidence"}]}],
            "inferenceConfig": {"maxTokens": 100, "temperature": 0},
        },
    )
    answer = BedrockClient(MODEL, client=client).complete("the rules", "the evidence", max_tokens=100)
    assert answer == "hello"


def test_the_guardrail_setting_fits_the_api_definition(runtime):
    client, stub = runtime
    stub.add_response(
        "converse",
        _response("hello"),
        {
            "modelId": MODEL,
            "system": [{"text": "s"}],
            "messages": [{"role": "user", "content": [{"text": "u"}]}],
            "inferenceConfig": {"maxTokens": 2000, "temperature": 0},
            "guardrailConfig": {"guardrailIdentifier": "gr-1", "guardrailVersion": "DRAFT"},
        },
    )
    BedrockClient(MODEL, guardrail_id="gr-1", client=client).complete("s", "u")


def test_this_check_would_notice_a_wrong_request(runtime):
    client, stub = runtime
    stub.add_response("converse", _response("hello"))
    with pytest.raises(ParamValidationError):
        client.converse(modelId=MODEL, messages=[{"role": "user", "content": "not a list of blocks"}])
    client.converse(modelId=MODEL, messages=[{"role": "user", "content": [{"text": "u"}]}])


def test_a_guardrail_block_is_a_rejected_investigation(runtime, pipeline, falco, cases):
    from investigator.bundle import build_bundle

    client, stub = runtime
    pipeline.ingest(fixture_bytes("s1_suspicious_process", "falco_alert.json"), falco)
    for _ in range(2):  # the investigator retries once
        stub.add_response("converse", _response("Sorry, I can't help.", stop="guardrail_intervened"))

    with pytest.raises(InvestigationRejected):
        Investigator(BedrockClient(MODEL, client=client)).investigate(build_bundle(cases.list()[0]))


def test_a_valid_answer_passes_through_unchanged(runtime):
    client, stub = runtime
    text = json.dumps({"synopsis": "s"})
    stub.add_response("converse", _response(text))
    assert BedrockClient(MODEL, client=client).complete("s", "u") == text
