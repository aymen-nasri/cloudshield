PYTHON ?= python3
CLUSTER := cloudshield-lab
CALICO_VERSION := v3.29.1
KYVERNO_VERSION := v1.19.2

.PHONY: install lint typecheck test schemas check infra-check lab-up lab-e2e lab-down core-up core-down demo console-demo demo-incident evals

install:
	$(PYTHON) -m pip install -e ".[dev,aws,k8s,postgres]"

lint:
	ruff check .
	ruff format --check .

typecheck:
	mypy services

test:
	pytest -q

schemas:
	$(PYTHON) scripts/export_schemas.py

check: lint typecheck test
	$(PYTHON) scripts/export_schemas.py --check

# Same checks as the CI "validate infrastructure" job; needs tofu, helm, kubeconform and kyverno.
infra-check:
	tofu fmt -check -recursive -diff infra/tofu
	cd infra/tofu/envs/lab && tofu init -backend=false -input=false && tofu validate
	helm lint --strict infra/helm/cloudshield
	helm template cloudshield infra/helm/cloudshield --namespace cloudshield \
		| kubeconform -strict -summary -kubernetes-version 1.31.0 -
	kubeconform -strict -summary -kubernetes-version 1.31.0 -schema-location default \
		-schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
		infra/k8s infra/policies/networkpolicies infra/policies/rbac infra/policies/kyverno/*.yaml
	kyverno test infra/policies/kyverno/tests

# --- Local lab (kind + Calico + Falco + demo app) -------------------------------------------
lab-up:
	kind create cluster --config infra/kind/cluster.yaml
	kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests/calico.yaml
	kubectl -n kube-system rollout status ds/calico-node --timeout=180s
	kubectl create namespace cloudshield --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f infra/k8s/demo-shop/shop.yaml
	kubectl apply -f infra/policies/networkpolicies/shop.yaml
	kubectl apply -f infra/policies/rbac/cloudshield-rbac.yaml
	kubectl apply -f infra/kind/probe.yaml
	kubectl create -f https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/install.yaml
	kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=300s
	for attempt in 1 2 3 4 5 6; do \
		kubectl apply -f infra/policies/kyverno/require-quarantine-exclusion.yaml && break; sleep 10; \
	done
	bash infra/kind/deploy-cloudshield.sh
	bash infra/kind/deploy-monitoring.sh
	kubectl apply -f infra/policies/kyverno/verify-cloudshield-images.yaml
	helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update
	helm upgrade --install falco falcosecurity/falco -n falco --create-namespace \
		-f infra/helm/falco-values.yaml \
		--set collectors.kubernetes.enabled=false \
		--set falcosidekick.config.webhook.customHeaders='Authorization:Bearer lab-falco-key' \
		--set-file 'customRules.cloudshield_rules\.yaml=detections/falco/cloudshield_rules.yaml'

lab-e2e:
	python scripts/lab_e2e.py --alert falco --admission

lab-down:
	kind delete cluster --name $(CLUSTER)

# --- Core services ------------------------------------------------------------------------
core-up:
	docker compose up -d --build

core-down:
	docker compose down

demo:
	$(PYTHON) scripts/demo.py --svg docs/demo.svg

console-demo:
	$(PYTHON) scripts/console_demo.py

demo-incident:
	$(PYTHON) scripts/replay_fixture.py detections/fixtures/s1_suspicious_process

evals:
	$(PYTHON) evals/run_evals.py
