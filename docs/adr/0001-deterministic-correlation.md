# ADR 0001: Deterministic correlation before machine learning

**Status:** accepted · 2026-10-28

## Context
CloudShield has to group events from Falco, GuardDuty and Wazuh into cases. A wrong merge hides
an incident inside another one; a missed merge splits one incident across analysts.

## Decision
Use ordered, explicit rules (`services/correlation/engine.py`): same pod UID within 15 minutes
(C-01), same EC2 instance within 30 minutes (C-02), same IAM principal within 60 minutes (C-03),
and never across account or cluster (C-04). Each link records the rule, a confidence and a
human-readable rationale.

## Consequences
- Every grouping can be explained and unit-tested with fixtures.
- No labeled training data is needed to start.
- Some related events will not be linked (for example, two pods of one compromised deployment).
  That gap is acceptable at M2 and is the first candidate for a smarter rule or a model later.
