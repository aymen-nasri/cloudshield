# ADR 0005: Approvals the responder checks for itself

**Status:** accepted

## Problem

Separating the responder from the API pod removed Kubernetes write access from the API, but the responder still believed the API about who had approved. A compromised API pod held the shared token, so it could ask the responder to quarantine or release any allowlisted pod with no human involved.

## Decision

Approvers sign an Ed25519 statement with a private key that only they hold. The responder holds only the public keys, and it refuses to run an action without enough valid signatures.

- **What's signed:** the proposal hash, the requester, the approver and the time. The hash doesn't cover the requester, and the self-approval rule depends on it, so it's signed too.
- **What the responder recomputes:** the hash, from the proposal it's asked to run. A signature can't be reused for another pod, action or proposal.
- **How many are needed:** this comes from the pod's live labels, so a proposal written without `cloudshield.io/tier: critical` still needs two signatures for a critical pod.
- **The signing tool:** `scripts/sign_approval.py` runs on the approver's machine. It recomputes the hash and prints what's being approved from the same data, so a tampered API can't show one action and have them sign another.

## Alternatives rejected

- **Signing with a key on the API pod, or a separate approval service holding a key.** The first is the same problem. The second moves it to another service, whose key would then be the target.
- **An HMAC derived from the analyst's token.** The API pod sees that token on every request, so it could derive the key.

## Consequences

- **The analyst console can't approve when this is on,** because the browser has no key. Approving means running the tool and calling the API. The in-process setups (the demo and `docker compose`) don't use the responder and don't need signatures.
- **Key management is now a real job.** Keys are created by hand and listed in a Secret, with no rotation or revocation beyond editing that Secret. The kind lab derives its key from a fixed seed.
- **Replays are limited, not impossible.** The responder remembers executed proposals in memory, so after a restart a signature could be replayed until its 15 minutes run out.

## What it doesn't protect against

- A compromised responder pod, which holds the write access itself.
- A compromised approver's machine or key.
- An approver who signs without reading. The tool shows the action, but it can't make them read it.
- The evidence an approver relies on. A compromised API could still show a misleading case, and the signature only binds the action.
- The Step Functions path, which has its own approval flow and doesn't use these signatures.
