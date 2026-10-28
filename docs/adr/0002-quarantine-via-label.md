# ADR 0002: Quarantine by label, default-deny and an enforced exclusion

**Status:** accepted · 2026-10-28

## Context
The first response action has to be reversible, preserve forensic state and work with Kubernetes
NetworkPolicy semantics. NetworkPolicies are additive allow-lists: a new "deny" policy cannot
override an existing allow, so "apply a deny-all policy to the bad pod" does not work.

## Decision
- Protected namespaces run `default-deny-all`.
- Every allow-policy excludes `cloudshield.io/quarantine=true` via `matchExpressions: NotIn`.
- Quarantine adds that label; rollback removes it.
- The Kyverno policy `require-quarantine-exclusion` rejects allow-policies without the exclusion.
- Verification checks that no allow-policy still selects the pod.

## Alternatives rejected
- **Delete the pod / scale to zero:** destroys memory and filesystem evidence; not reversible.
- **Cilium/Calico deny policies:** would work, but ties the core action to one CNI.

## Consequences
- Works on any CNI that enforces standard NetworkPolicy (VPC CNI with network policy, Calico).
- `hostNetwork` pods are out of reach and must be escalated instead.
- Already-open connections may survive depending on the CNI; an egress probe is planned (M4).
