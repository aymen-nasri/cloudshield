# Skills this project demonstrates

What is built and tested in each domain, and what is written as code or planned. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only · 🔬 run on an emulator or a stand-in, not on real AWS.

## Skills this project demonstrates

| Domain | Built and tested here | Written as code (🧩) or planned (📐) |
|---|---|---|
| **AWS** | GuardDuty findings, EKS Pod Identity and EC2 lookups, S3 evidence store, SQS consumer | 🧩 VPC, EKS, IAM, EventBridge, S3 Object Lock, budgets, GitHub OIDC, Step Functions + Lambda, Bedrock client · 📐 CloudTrail, Security Hub, Secrets Manager |
| **Linux** | Wazuh alert ingestion, the host-compromise scenario | 🧩 hardening and Wazuh enrolment with Ansible |
| **Kubernetes** | Helm deployment on kind, workload metadata, NetworkPolicy quarantine traffic-tested on kind, least-privilege RBAC checked live, Kyverno admission enforced in the lab, including image signatures | 🧩 EKS |
| **Networking** | Pod-to-pod policy and egress control with Calico | 🧩 VPC Flow Logs · 📐 Security Group isolation, Cilium/Hubble |
| **Detection engineering** | Custom Falco rules firing on a live attack in the kind lab, five replayable attack scenarios, MITRE ATT&CK tagging | — |
| **Data engineering** | OCSF normalization, idempotent ingestion, PostgreSQL modeling and migrations | 🧩 dead-letter queue · 📐 OpenSearch |
| **AI engineering** | Runbook retrieval, structured outputs, citation enforcement, prompt-injection defenses, evaluation harness | 🧩 Bedrock client · 📐 vector search, LangGraph, MCP |
| **Software engineering** | FastAPI services, Pydantic contracts, state machines, hash-chained audit log, REST API and console | — |
| **DevOps** | GitHub Actions, Docker Compose and a kind cluster tested in CI, Helm, Prometheus and Grafana | 🧩 OpenTofu, Ansible · 📐 Argo CD, OpenTelemetry |
| **DevSecOps** | Gitleaks, Trivy, signed SBOM, keyless Cosign signing, dependency review, Dependabot, Kyverno admission, infrastructure validation | 🧩 GitHub OIDC to AWS |

> **How this goes beyond a typical SOC-automation lab:** a "Wazuh → SOAR → block IP" pipeline proves alert collection and automated containment. CloudShield goes further in three ways: **cross-layer resource context**, **investigation quality with provenance**, and **safety-aware, reversible, auditable response**.
