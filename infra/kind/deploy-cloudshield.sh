#!/usr/bin/env bash
# Build CloudShield from this checkout and install it in the kind lab with its Helm chart.
# Run this before enforcing the image policy: only main's CI signs images, so a local build is unsigned.
set -euo pipefail
cd "$(dirname "$0")/../.."

docker build -t cloudshield/core:lab .
kind load docker-image cloudshield/core:lab --name cloudshield-lab

# Lab-only credentials. scripts/lab_e2e.py and Falcosidekick use these same tokens.
analysts=$(python3 -c '
import hashlib, json
digest = lambda token: hashlib.sha256(token.encode()).hexdigest()
print(json.dumps({
    digest("alice-lab"): {"id": "analyst:alice", "roles": ["analyst"]},
    digest("bob-lab"): {"id": "analyst:bob", "roles": ["incident-responder"]},
}))')
kubectl -n cloudshield create secret generic cloudshield-ingest-credentials \
  --from-literal=CLOUDSHIELD_FALCO_TOKEN=lab-falco-key \
  --from-literal=CLOUDSHIELD_ANALYSTS="$analysts" \
  --dry-run=client -o yaml | kubectl apply -f -

# Kubernetes fills the responder and prober token Secrets shortly after they are created.
for secret in cloudshield-responder-token cloudshield-prober-token; do
  until [ -n "$(kubectl -n cloudshield get secret "$secret" -o jsonpath='{.data.token}')" ]; do
    sleep 1
  done
done

helm upgrade --install cloudshield infra/helm/cloudshield -n cloudshield \
  -f infra/helm/cloudshield/values-kind-lab.yaml --wait --timeout 3m
