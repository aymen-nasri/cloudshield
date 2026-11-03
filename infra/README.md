# infra/

Everything CloudShield runs on, as code: a local kind lab that CI builds on every pull request, and an AWS lab in OpenTofu.

Back to the [project README](../README.md). Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 planned.

| Folder | What it defines | Status | Checked by |
|---|---|---|---|
| [`kind/`](kind) | The three-node lab cluster (Calico instead of kindnet, so NetworkPolicies are enforced) and the curl probe pod the verifier tests traffic from | ✅ | the `kind lab` CI job |
| [`k8s/demo-shop/`](k8s/demo-shop) | The protected demo app: `checkout` and `cart` services in the `shop` namespace, Pod Security `restricted` | ✅ | kubeconform, the `kind lab` CI job |
| [`policies/networkpolicies/`](policies/networkpolicies) | Default-deny plus allow-policies that each exclude `cloudshield.io/quarantine=true`, so one label quarantines a pod | ✅ traffic-tested | the `kind lab` CI job |
| [`policies/rbac/`](policies/rbac) | Three identities with no overlap: a read-only investigator, a responder that may only patch pods in `shop`, and a prober that may only exec into the probe pod | ✅ refusals tested | the `kind lab` CI job |
| [`policies/kyverno/`](policies/kyverno) | Admission rules: every allow-policy must keep the quarantine exclusion; only signed CloudShield images may run | ✅ quarantine guard enforced in the lab · 🧩 image verification | `kyverno test` in CI; the `kind lab` job checks a leaky policy is rejected |
| [`helm/`](helm) | The CloudShield chart, and the Falco values that load CloudShield's custom rules | 🧩 chart · ✅ Falco values | `helm lint`, kubeconform; the `kind lab` job installs Falco with these values |
| [`ansible/`](ansible) | Linux host hardening, Wazuh agent enrolment and the signed Wazuh → CloudShield integration | 🧩 | `ansible-playbook --syntax-check` |
| [`tofu/envs/lab/`](tofu/envs/lab) | The AWS lab: VPC with flow logs, EKS with Pod Identity, GuardDuty → EventBridge → SQS with a dead-letter alarm, S3 evidence bucket with Object Lock and KMS, ECR, budgets, GitHub OIDC role | 🧩 | `tofu fmt`, `tofu validate` |

## How the quarantine works

The `shop` namespace runs a **default-deny** policy. Every allow-policy selects its pods with `cloudshield.io/quarantine NotIn ["true"]`. Labelling one pod therefore drops it out of every allow-policy at once, while the pod keeps running for forensics. Removing the label is the rollback. A Kyverno rule rejects any new allow-policy that forgets the exclusion. See [ADR 0002](../docs/adr/0002-quarantine-via-label.md).

## Commands

```bash
make lab-up       # kind + Calico + shop app + NetworkPolicies + RBAC + probe + Falco
make lab-e2e      # scenario S1 against the cluster, with real traffic checks
make lab-down
make infra-check  # tofu validate, helm lint, kubeconform, kyverno test, Ansible syntax check
```

The AWS lab (budget alarms first, destroy after each session) is described in [ADR 0004](../docs/adr/0004-lab-account-and-state.md).
