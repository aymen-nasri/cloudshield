#!/usr/bin/env bash
# Build CloudShield from this checkout and install it in the kind lab with its Helm chart.
# Run this before enforcing the image policy: only main's CI signs images, so a local build is unsigned.
set -euo pipefail
cd "$(dirname "$0")/../.."

docker build -t cloudshield/core:lab .
kind load docker-image cloudshield/core:lab --name cloudshield-lab

# PostgreSQL first: CloudShield applies its migrations when it starts. Keep the password across re-runs.
kubectl apply -f infra/kind/postgres.yaml
password=$(kubectl -n cloudshield-data get secret postgres -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)
[ -n "$password" ] || password=$(openssl rand -hex 16)
kubectl -n cloudshield-data create secret generic postgres --from-literal=password="$password" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n cloudshield-data rollout status statefulset/postgres --timeout=3m

# Lab-only credentials. scripts/lab_e2e.py and Falcosidekick use these same tokens.
analysts=$(python3 -c '
import hashlib, json
digest = lambda token: hashlib.sha256(token.encode()).hexdigest()
print(json.dumps({
    digest("alice-lab"): {"id": "analyst:alice", "roles": ["analyst"]},
    digest("bob-lab"): {"id": "analyst:bob", "roles": ["incident-responder"]},
    digest("prometheus-lab"): {"id": "service:prometheus", "roles": ["viewer"]},
}))')
kubectl -n cloudshield create secret generic cloudshield-ingest-credentials \
  --from-literal=CLOUDSHIELD_FALCO_TOKEN=lab-falco-key \
  --from-literal=CLOUDSHIELD_ANALYSTS="$analysts" \
  --from-literal=CLOUDSHIELD_DATABASE_URL="postgresql://cloudshield:$password@postgres.cloudshield-data.svc:5432/cloudshield" \
  --dry-run=client -o yaml | kubectl apply -f -

# Kubernetes fills the responder and prober token Secrets shortly after they are created.
for secret in cloudshield-responder-token cloudshield-prober-token; do
  until [ -n "$(kubectl -n cloudshield get secret "$secret" -o jsonpath='{.data.token}')" ]; do
    sleep 1
  done
done

helm upgrade --install cloudshield infra/helm/cloudshield -n cloudshield \
  -f infra/helm/cloudshield/values-kind-lab.yaml --wait --timeout 3m
