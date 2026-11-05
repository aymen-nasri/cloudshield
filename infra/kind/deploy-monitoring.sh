#!/usr/bin/env bash
# Install Prometheus and Grafana in the kind lab. Prometheus scrapes CloudShield as a read-only
# analyst; infra/kind/deploy-cloudshield.sh registers the token below.
set -euo pipefail
cd "$(dirname "$0")/monitoring"

kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
configmap() {
  name=$1; shift
  kubectl -n monitoring create configmap "$name" "$@" --dry-run=client -o yaml | kubectl apply -f -
}
configmap prometheus-config --from-file=prometheus.yml
configmap prometheus-rules --from-file=alerts.yml
configmap grafana-datasources --from-file=grafana-datasource.yaml
configmap grafana-dashboard-providers --from-file=grafana-dashboards.yaml
configmap grafana-dashboards --from-file=cloudshield-dashboard.json
kubectl -n monitoring create secret generic prometheus-scrape-token --from-literal=token=prometheus-lab \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f workloads.yaml
kubectl -n monitoring rollout status deploy/prometheus --timeout=3m
kubectl -n monitoring rollout status deploy/grafana --timeout=3m
