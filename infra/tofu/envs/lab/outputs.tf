output "cluster_name" {
  value = module.eks.cluster_name
}

output "findings_queue_url" {
  value = aws_sqs_queue.findings.url
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.bucket
}

output "evidence_kms_key_arn" {
  value = aws_kms_key.evidence.arn
}

output "ecr_repository_url" {
  value = aws_ecr_repository.core.repository_url
}

output "ci_publish_role_arn" {
  description = "Set as the AWS_ROLE_ARN repository variable to enable the publish job in CI."
  value       = aws_iam_role.ci_publish.arn
}
