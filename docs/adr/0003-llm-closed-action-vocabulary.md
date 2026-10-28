# ADR 0003: The LLM returns validated data from a closed action vocabulary

**Status:** accepted · 2026-10-28

## Context
Evidence contains attacker-controlled text (command lines, log lines, alert descriptions).
Prompt injection cannot be fully prevented inside a model, so safety cannot depend on the model.

## Decision
- The investigator returns one JSON object validated against `common.models.Investigation`.
- `containment_options[].action_type` is a `Literal` of three values; anything else fails parsing.
- Every fact must cite at least one event ID, and every cited ID must exist in the bundle that was
  sent. Targets must be entities from the bundle.
- Evidence is wrapped in nonce-tagged `<untrusted_evidence>` blocks and secrets are redacted first.
- The model holds no credentials. Execution needs a policy decision and a hash-bound human
  approval, both outside the model.

## Consequences
- A successful injection can at worst produce a misleading summary that an analyst reviews; it
  cannot produce an action the policy engine would accept on its own.
- Rejected outputs are retried once with validator messages only (never echoing evidence text).
