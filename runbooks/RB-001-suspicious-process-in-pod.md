---
id: RB-001
title: Suspicious process in a Kubernetes pod
applies_to: [process.unexpected_execution, process.remote_script_execution, guardduty.Execution:Runtime/NewBinaryExecuted]
mitre: [T1059, T1105, T1609]
owner: security
reviewed: 2026-10-28
---

# Suspicious process in a Kubernetes pod

## 1. Confirm what ran
- Read the exact command line from the Falco evidence. Note the parent process and user.
- Check for a matching GuardDuty Runtime Monitoring finding for the same pod UID.
- Check the Kubernetes audit log for `pods/exec` or `pods/attach` on the pod in the preceding
  15 minutes, and who performed it.

## 2. Establish blast radius
- Resolve pod -> deployment -> service account -> IAM role (EKS Pod Identity).
- List what the IAM role can access. Treat this as *configured* access, not proven use.
- Search CloudTrail for API calls by the role's sessions since the first suspicious event.
- Check flow logs for connections to the IP or domain in the command line.

## 3. Decide on containment
- Prefer `k8s.pod.quarantine_label`: it cuts network access but keeps the pod running so memory,
  filesystem and process state stay available for forensics.
- Do not delete the pod or scale the deployment to zero before evidence is preserved.
- Check that the deployment has enough healthy replicas to absorb losing this one.

## 4. After containment
- Confirm verification passed (label present, no allow-policy selects the pod).
- Rotate any credential the pod could read if CloudTrail shows use from the pod.
- Open a follow-up to fix the root cause (image, exposed exec permissions, leaked CI token).
