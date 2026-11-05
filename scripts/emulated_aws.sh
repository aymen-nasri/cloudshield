#!/usr/bin/env bash
# The AWS paths against Moto, an AWS emulator: no account, no cost, and not proof of real AWS behavior.
# Applies the lab's real OpenTofu files to the emulator, then runs tests/test_emulated_aws.py on them.
set -euo pipefail
cd "$(dirname "$0")/.."

endpoint=http://127.0.0.1:5000
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=eu-west-1 # emulator only
lab=infra/tofu/envs/lab

moto_server -H 127.0.0.1 -p 5000 >moto.log 2>&1 &
moto_pid=$!
cleanup() {
  kill "$moto_pid" 2>/dev/null || true
  rm -rf "$lab/emulator_override.tf" "$lab/.terraform" "$lab/.terraform.lock.hcl" "$lab"/terraform.tfstate*
}
trap cleanup EXIT
for _ in $(seq 1 30); do
  curl -sf "$endpoint/moto-api/" >/dev/null && break
  sleep 1
done

# Point the real configuration at the emulator, with no change to the files under test.
cat >"$lab/emulator_override.tf" <<EOF
terraform {
  backend "local" {}
}

provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints {
    cloudwatch = "$endpoint"
    events     = "$endpoint"
    guardduty  = "$endpoint"
    iam        = "$endpoint"
    kms        = "$endpoint"
    s3         = "$endpoint"
    sns        = "$endpoint"
    sqs        = "$endpoint"
    sts        = "$endpoint"
  }
}
EOF

# The detection path and the evidence bucket. EKS, the VPC, budgets and OIDC aren't applied here.
tofu -chdir="$lab" init -input=false -no-color
tofu -chdir="$lab" apply -input=false -auto-approve -no-color \
  -var budget_alert_email=lab@example.com \
  -target=aws_guardduty_detector.lab \
  -target=aws_sqs_queue.findings \
  -target=aws_sqs_queue.findings_dlq \
  -target=aws_sqs_queue_policy.findings \
  -target=aws_cloudwatch_event_rule.guardduty_findings \
  -target=aws_cloudwatch_event_target.to_sqs \
  -target=aws_cloudwatch_metric_alarm.dlq_not_empty \
  -target=aws_s3_bucket.evidence \
  -target=aws_s3_bucket_versioning.evidence \
  -target=aws_s3_bucket_object_lock_configuration.evidence \
  -target=aws_s3_bucket_server_side_encryption_configuration.evidence \
  -target=aws_s3_bucket_public_access_block.evidence

CLOUDSHIELD_EMULATED_AWS=$endpoint python -m pytest tests/test_emulated_aws.py -v -rs --no-header -p no:cacheprovider
