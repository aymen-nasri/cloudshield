# Evaluation

KPIs, quality gates and the test catalog. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only.

## Evaluation: KPIs and test catalog

CloudShield's benefits are claimed only once they have been **measured**. Each KPI has a method and a quality gate; results are recorded per milestone.

| Metric | How it is measured | Quality gate (lab) | Result |
|---|---|---|---|
| Case assembly time | Time to gather the evidence for a scripted incident, CloudShield vs a manual baseline | Faster than the recorded manual baseline | ⏳ M4 |
| Evidence completeness | Required artifacts linked ÷ expected artifacts in the scenario | All known required lab artifacts linked | ⏳ M2 |
| Correlation precision | Correct groupings vs false merges on a labeled fixture set | Zero cross-incident merges | ⏳ M2 |
| Source provenance | Share of AI factual statements with valid event IDs | 100% of material conclusions cited | ⏳ M3 |
| Safe action rejection | Unsafe or unapproved attempts blocked | 100% of negative policy tests pass | ⏳ M4 |
| Execution correctness | Approved action applied exactly once, with a result check | Repeatable positive and failure-path tests | ⏳ M4 |
| Detection quality | Expected Falco / GuardDuty fixtures registered | Recall and false alerts documented on the lab set | ⏳ M2 |
| Platform reliability | Backlog handling, adapter failure, health state | No silent loss of critical demo events | ⏳ M2 |
| Cost control | Measured AWS, storage and inference consumption | Within the preset lab budget | ⏳ M1+ |

### Test catalog

| ID | Test | Expected behavior | Milestone | Status |
|---|---|---|---|---|
| T-01 | **Happy path** | Valid Falco alert → correct case → grounded report → approved action → verification | M4 | 🧪 (offline baseline model) |
| T-02 | **Duplicate delivery** | One source event produces exactly one canonical finding and case link | M2 | 🧪 |
| T-03 | **Out-of-order events** | The timeline is rebuilt by event time, not arrival order | M2 | 🧪 |
| T-04 | **Sensor outage** | Coverage is marked degraded; CloudShield doesn't report "all clear" | M2 | 🧪 |
| T-05 | **Ambiguous asset mapping** | The identity stays unresolved and is displayed as such | M2 | 🧪 |
| T-06 | **Prompt injection in a log** | Malicious instructions stay data and never invoke privileged tools | M3 | 🧪 |
| T-07 | **Approval denied or expired** | No action occurs | M4 | 🧪 |
| T-08 | **Execution timeout / partial failure** | Status and manual escalation are visible | M4 | 🧪 |
| T-09 | **High-volume burst** | Queue backpressure and cost limits hold | M5 | ⬜ |

🧪 = covered by automated tests in [`tests/`](../tests), with fakes standing in for Kubernetes and AWS · ✅ = also demonstrated on the lab cluster · ⬜ = not yet covered
