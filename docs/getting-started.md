# Getting started

Install, test, run the core API, replay an incident, run the kind lab and bring up the AWS lab. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only · 🔬 run on an emulator or a stand-in, not on real AWS.

## Getting started

> **Status:** the core API, PostgreSQL persistence (events, cases, entity graph, hash-chained audit log), Kubernetes/AWS enrichment, the full proposal → approval → execution → verification API, the AI investigation API with runbook retrieval (offline baseline model; Bedrock when configured) and the test suite run today. So do the analyst console and post-incident reports. The kind lab runs in CI on every pull request; the AWS lab is defined in code but has not been brought up yet (M1).

**Prerequisites:** Python 3.12+, Docker, Make. For the local lab: kind, kubectl, Helm. For the AWS lab: OpenTofu, the AWS CLI and a dedicated AWS account.

```bash
git clone https://github.com/aymen-nasri/cloudshield.git
cd cloudshield
make install         # editable install with dev, AWS, Kubernetes and PostgreSQL extras
make check           # ruff, mypy, pytest, schema drift check
make evals           # score the investigator evaluation candidates
```

The store contract tests also run against PostgreSQL when a disposable database is available (CI always runs them against a `postgres:16` service):

```bash
CLOUDSHIELD_TEST_DATABASE_URL=postgresql://user@localhost:5432/cloudshield_test pytest -m postgres
```

**Run the core API and replay scenario S1** (CI runs these steps on every pull request, in [`scripts/compose_check.sh`](../scripts/compose_check.sh)):

```bash
cp .env.example .env # then set real values
make core-up         # core API (applies migrations) and PostgreSQL; OpenSearch is started for the planned search
set -a; . ./.env; set +a
make demo-incident   # replays GuardDuty + Falco out of order; both land in one case
make console-demo    # or: the console on demo data at http://127.0.0.1:8090/console
curl -H "authorization: Bearer $CLOUDSHIELD_ANALYST_TOKEN" localhost:8080/v1/cases
docker compose restart core && curl -H "authorization: Bearer $CLOUDSHIELD_ANALYST_TOKEN" localhost:8080/v1/cases   # the case survives a restart
```

**Verify the published image** (public, no login needed; requires [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/)):

```bash
cosign verify ghcr.io/aymen-nasri/cloudshield:main \
  --certificate-identity https://github.com/aymen-nasri/cloudshield/.github/workflows/ci.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

**Local Kubernetes lab:**

```bash
make lab-up          # kind + Calico + shop app + NetworkPolicies + RBAC + Kyverno + PostgreSQL + CloudShield + Prometheus + Grafana + Falco
make lab-e2e         # scenario S1 on the cluster, with real traffic probes (CI runs it on every PR)
make lab-down
```

**AWS lab** (see [ADR 0004](adr/0004-lab-account-and-state.md)):

```bash
cd infra/tofu/envs/lab
cp terraform.tfvars.example terraform.tfvars
tofu init -backend-config="bucket=<state-bucket>" -backend-config="region=eu-west-1"
tofu apply -target=aws_budgets_budget.lab   # budget alarms first
tofu apply                                  # VPC, EKS, GuardDuty → EventBridge → SQS, S3 evidence, IAM
tofu destroy                                # after each demo window
```
