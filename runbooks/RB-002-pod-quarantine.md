---
id: RB-002
title: Applying and rolling back a pod quarantine
applies_to: [k8s.pod.quarantine_label, k8s.pod.remove_quarantine_label]
owner: security
reviewed: 2026-10-28
---

# Applying and rolling back a pod quarantine

## How it works
Protected namespaces run a default-deny NetworkPolicy. Every allow-policy excludes pods labelled
`cloudshield.io/quarantine=true` (enforced by the Kyverno policy `require-quarantine-exclusion`).
Adding the label removes the pod from all allow-policies, so only default-deny applies to it.

## Before approving
- The target pod UID in the proposal matches the live pod.
- The dry-run passed.
- The impact preview lists the callers that will lose this replica, and the deployment has at
  least two other healthy replicas.

## Known limits
- Whether already-open connections are cut depends on the CNI. Verification checks policy state;
  an egress probe is planned (M4).
- A pod in `hostNetwork` mode is not governed by NetworkPolicy. Quarantine does not apply; escalate.

## Rollback
Approve `k8s.pod.remove_quarantine_label` for the same pod. Verification confirms the label is
gone and the pod is selected by its normal allow-policies again.
