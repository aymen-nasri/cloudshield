# Incident scenarios

The eight attack scenarios, their signals, what each one proves and its MITRE ATT&CK mapping. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only · 🔬 run on an emulator or a stand-in, not on real AWS.

## Incident scenarios and MITRE ATT&CK mapping

| # | Scenario | Signals and context | Safe demonstration objective | ATT&CK / ATLAS |
|---|---|---|---|---|
| S1 | **Suspicious process in a pod** *(reference)* 🧪 | Falco, GuardDuty Runtime, K8s audit, pod/SA/IAM context | Full loop: detect → investigate → approve → quarantine → verify | T1609, T1059, T1105 |
| S2 | Stolen pod credentials used outside AWS 🧪 | GuardDuty credential-exfiltration and discovery findings on the pod's IAM role | Joined on the IAM principal (C-03), and to the pod's own case when its alert is present: a runtime alert and an identity finding in one case | T1078.004, T1552.005, T1580 |
| S3 | Linux host compromise indicator 🧪 | Wazuh brute force, login after failures, new cron file; EC2 instance label | One host case via C-02 that **preserves evidence**; no automated containment (host isolation is not allowlisted) | T1110, T1078, T1053.003 |
| S4 | Unexpected pod egress | Falco, Hubble, VPC Flow Logs, ownership, NetworkPolicy | Shows why a network restriction needs dependency review | T1071, T1041 |
| S5 | Multiple correlated findings | Two event types for one workload in a time window | Correct grouping, with evidence links and the documented rule rationale | — |
| S6 | False positive / benign change 🧪 | One low-severity interactive shell, no second detector | CloudShield records it but **declines** to recommend containment | T1609 |
| S7 | Failed response integration | Simulated timeout, IAM denial or stale target | Safe failure, audit, retry limit and escalation | — |
| S8 | Unsafe AI instruction in a log 🧪 | Adversarial text inside an ingested event | Proves the model can't gain write access or bypass review | ATLAS AML.T0051 · OWASP LLM01 |

🧪 = a replayable fixture in [`detections/fixtures/`](../detections/fixtures) with an `expected.yaml`; [`tests/test_scenarios.py`](../tests/test_scenarios.py) replays every one in CI and checks the case count, correlation rules, severity and whether containment is recommended. S1 is the reference scenario used by the demo.
