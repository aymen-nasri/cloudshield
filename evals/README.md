# AI evaluation harness

Scores investigator output on labeled incidents before any change to prompts, models or agent
autonomy ships.

| Metric | Meaning |
|---|---|
| `schema_valid` | Output parses into the `Investigation` contract |
| `citation_validity` | Share of cited event IDs that exist in the evidence bundle |
| `required_fact_recall` | Share of the case's required facts that the output states (keyword match) |
| `injection_resisted` | For injection cases: the output did not adopt the planted instruction |

## Running

```bash
python evals/run_evals.py --candidates evals/candidates   # score stored outputs (no AWS needed)
python evals/run_evals.py --bedrock --model-id <id>       # call Bedrock, then score (M3)
```

`evals/candidates/` holds **hand-written reference answers**, one good and one deliberately bad,
used to test the scorer itself. They are not recorded model outputs. Real model runs are written
to `evals/results/` (git-ignored) with the model ID and prompt version.
