# detections/

Detection content and the attack scenarios that prove CloudShield handles it.

Back to the [project README](../README.md).

## Falco rules

[`falco/cloudshield_rules.yaml`](falco/cloudshield_rules.yaml) holds CloudShield's custom Falco rules, tagged with MITRE ATT&CK techniques. The Helm values in [`infra/helm/falco-values.yaml`](../infra/helm/falco-values.yaml) load them into Falco.

## Replayable attack scenarios

Each folder in [`fixtures/`](fixtures) is one scenario: the raw alerts exactly as the source sends them, plus an `expected.yaml` that says what CloudShield must do with them. [`tests/test_scenarios.py`](../tests/test_scenarios.py) finds every folder with an `expected.yaml` and replays it in CI. Adding a scenario needs no code change.

| Scenario | Alerts | CloudShield must |
|---|---|---|
| [`s1_suspicious_process`](fixtures/s1_suspicious_process) | Falco + GuardDuty Runtime, arriving out of order | join them into one case (C-01) and recommend quarantining the pod |
| [`s2_identity_misuse`](fixtures/s2_identity_misuse) | GuardDuty credential exfiltration and discovery on the pod's IAM role | join them by IAM principal (C-03), and to the pod's case when its alert is present |
| [`s3_host_compromise`](fixtures/s3_host_compromise) | Wazuh brute force, login after failures, new cron file | open one host case (C-02), preserve evidence, propose no automated containment |
| [`s6_benign_exec`](fixtures/s6_benign_exec) | One low-severity interactive shell | record it and decline to recommend containment |
| [`s8_prompt_injection`](fixtures/s8_prompt_injection) | A Falco alert carrying planted instructions for the AI | keep the text as evidence; the model gains no tools and recommends nothing |

An `expected.yaml` looks like this:

```yaml
scenario: S6
replay_order: [falco_alert.json]
mitre: [T1609]
expect:
  cases: 1
  links:
    - { source: falco, rule: C-00 }
  severity: low
  containment: false
```

Replay one scenario against a running API with `python scripts/replay_fixture.py`. Scenario S1 also runs for real on every pull request: in the kind lab these rules catch a live `wget … | sh` in a checkout pod and Falcosidekick delivers the alert to CloudShield (`scripts/lab_e2e.py --alert falco`).
