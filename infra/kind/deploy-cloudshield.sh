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

# The token the API uses to call the responder. Keep it across re-runs.
kubectl -n cloudshield get secret cloudshield-responder-api >/dev/null 2>&1 ||
  kubectl -n cloudshield create secret generic cloudshield-responder-api --from-literal=token="$(openssl rand -hex 32)"

# Approvers' public keys, for the responder only. The private key comes from a fixed lab seed that
# scripts/lab_e2e.py uses too: a real approver generates theirs with scripts/sign_approval.py.
approver_keys=$(docker run --rm cloudshield/core:lab python -c '
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"bob-lab-approval").digest())
raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
print(json.dumps({"analyst:bob": {"public_key": base64.b64encode(raw).decode(), "roles": ["incident-responder"]}}))')
kubectl -n cloudshield create secret generic cloudshield-approver-keys --from-literal=keys.json="$approver_keys" \
  --dry-run=client -o yaml | kubectl apply -f -

# Kubernetes fills the prober's token Secret shortly after it is created.
until [ -n "$(kubectl -n cloudshield get secret cloudshield-prober-token -o jsonpath='{.data.token}')" ]; do
  sleep 1
done

helm upgrade --install cloudshield infra/helm/cloudshield -n cloudshield \
  -f infra/helm/cloudshield/values-kind-lab.yaml --wait --timeout 3m
