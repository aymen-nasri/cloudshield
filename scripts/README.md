# scripts/

Runnable entry points. Each one drives CloudShield's real code; the only difference between them is how much of the outside world is real.

Back to the [project README](../README.md).

| Script | What it does | Kubernetes | AWS | Checked in CI |
|---|---|---|---|---|
| [`demo.py`](demo.py) | Scenario S1 through the HTTP API, from two alerts to a verified quarantine and the audit chain. `--svg` and `--report` write the images and report used in the README | simulated | simulated | `tests/test_demo.py` |
| [`lab_e2e.py`](lab_e2e.py) | Scenario S1 against the kind lab. With `--alert falco` (what CI runs) it attacks a live pod and waits for Falco's real alert; by default it replays the S1 alert. Then it quarantines the pod as the responder identity, prove with real traffic that it is cut off and that rollback restores it, check RBAC refusals | **real** (kind) | none | the `kind lab` job |
| [`console_demo.py`](console_demo.py) | Serves the analyst console on demo data at http://127.0.0.1:8090/console | simulated | simulated | `tests/test_console.py` |
| [`replay_fixture.py`](replay_fixture.py) | Sends a scenario's alerts from `detections/fixtures/` to a running API | n/a | n/a | — |
| [`export_schemas.py`](export_schemas.py) | Writes the JSON Schemas in `schemas/` from the Pydantic contracts | n/a | n/a | the schema drift check |

```bash
python scripts/demo.py                       # no setup needed
make lab-up && python scripts/lab_e2e.py     # needs Docker, kind, kubectl and Helm
```
