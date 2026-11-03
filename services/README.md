# services/

CloudShield's Python code: one FastAPI app (`core/`) wiring together small packages with one job each. Every package works against an interface (a `Protocol`), so tests swap in in-memory stores, a simulated Kubernetes API or the offline model, and production swaps in PostgreSQL, the real cluster and Bedrock.

Back to the [project README](../README.md).

## The path of one alert

```text
ingestion/  ->  enrichment/  ->  correlation/  ->  cases/  ->  investigator/  ->  policy/ + response/  ->  responder/  ->  reporting/
 normalize      pod -> IAM       join events       timeline    cited summary      gate + approvals       act + verify     report
```

## Packages

| Package | What it does | Key files | Tested in |
|---|---|---|---|
| [`common/`](common) | Pydantic contracts shared by everything: `NormalizedEvent`, `Investigation`, `ResponseProposal` | `models.py` | every test |
| [`core/`](core) | App factory, settings from the environment, analyst authentication | `app.py`, `auth.py` | `test_api.py` |
| [`ingestion/`](ingestion) | Source adapters (Falco, GuardDuty, Wazuh) to OCSF, fail-closed producer auth, dedup, raw evidence with SHA-256, SQS worker, sensor coverage | `adapters/`, `pipeline.py`, `auth.py`, `evidence.py` | `test_adapters.py`, `test_ingestion_and_correlation.py`, `test_coverage.py` |
| [`enrichment/`](enrichment) | Read-only lookups pod → deployment → service account → IAM role → EC2 instance, plus the entity graph | `context.py`, `enricher.py`, `graph.py` | `test_enrichment.py` |
| [`correlation/`](correlation) | Rules C-01 to C-04: join by pod UID, instance or IAM principal; never across accounts or clusters | `engine.py` | `test_ingestion_and_correlation.py`, `test_scenarios.py` |
| [`cases/`](cases) | Cases, timelines, the proposal state machine, the hash-chained audit log, SQL migrations | `store.py`, `state.py`, `audit.py`, `migrations/` | `test_audit_and_state.py`, `test_store_contract.py` |
| [`storage/`](storage) | PostgreSQL connection pool and the PostgreSQL versions of every store | `postgres.py`, `database.py` | `test_store_contract.py` (both backends) |
| [`investigator/`](investigator) | Evidence bundles marked untrusted, redaction, runbook retrieval, prompt, citation validation, offline baseline model, Bedrock client | `bundle.py`, `validate.py`, `workflow.py`, `offline.py`, `bedrock.py` | `test_investigator.py`, `test_investigation_flow.py`, `test_runbooks.py` |
| [`policy/`](policy) | The deterministic policy gate and the action allowlist (data only), hash-bound expiring approvals | `engine.py`, `approvals.py`, `policies/actions.yaml` | `test_policy.py` |
| [`response/`](response) | Propose → dry-run → approve → execute → verify, exactly once, never approved by the requester | `service.py`, `router.py` | `test_response_flow.py`, `test_response_api.py` |
| [`responder/`](responder) | The quarantine itself: label the pod, verify policy state and real traffic (an allowed peer must be blocked, then connect again after rollback), roll back; Lambda handler and Step Functions definition for AWS | `quarantine.py`, `executor.py`, `statemachine/` | `test_responder.py`, `test_statemachine.py`, the kind lab job |
| [`console/`](console) | The analyst incident page: static HTML and JS served by the API, text nodes only, strict CSP | `static/app.js` | `test_console.py` |
| [`reporting/`](reporting) | The post-incident report in Markdown, built only from recorded evidence, attacker text escaped | `report.py` | `test_report.py` |

## Rules every package follows

- **No package can reach production on its own.** The investigator has no write tools, the policy engine only reads data, and only `responder/` holds an identity that can change anything.
- **Unknown stays unknown.** A lookup that fails leaves the field unresolved; nothing is guessed.
- **Everything that matters is audited.** Ingest, investigation, proposal, approval, execution and verification each append to the hash-chained audit log.

## Run the tests

```bash
make check                                  # ruff, mypy, pytest, schema drift check
pytest tests/test_response_flow.py -q       # one area
```
