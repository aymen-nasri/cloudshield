# runbooks/

The curated, reviewed corpus the AI investigator retrieves from. Only these documents are treated as trusted reference text; everything that comes from an alert is treated as untrusted evidence.

Back to the [project README](../README.md).

| Runbook | Used for |
|---|---|
| [RB-001](RB-001-suspicious-process-in-pod.md) | Suspicious process in a Kubernetes pod |
| [RB-002](RB-002-pod-quarantine.md) | Quarantining a pod with the label, verifying it and rolling it back |

## How retrieval works

Each runbook starts with front matter. [`services/investigator/runbooks.py`](../services/investigator/runbooks.py) matches a case's event types (`applies_to`) and ATT&CK techniques (`mitre`) against it, and passes the matching sections to the model with their document IDs so the answer can cite them.

```yaml
---
id: RB-001
title: Suspicious process in a Kubernetes pod
applies_to: [process.unexpected_execution, process.remote_script_execution]
mitre: [T1059, T1105, T1609]
owner: security
reviewed: 2026-10-28
---
```

A runbook change goes through a pull request like code. `tests/test_runbooks.py` checks that every runbook parses and that the reference scenario retrieves the right one.
