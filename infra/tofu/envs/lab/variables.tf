variable "region" {
  description = "AWS region for the lab."
  type        = string
  default     = "eu-west-1"
}

variable "cluster_name" {
  description = "EKS cluster name. Must match CLOUDSHIELD_CLUSTER."
  type        = string
  default     = "cs-lab-eks"
}

variable "monthly_budget_usd" {
  description = "AWS Budgets limit for the lab account. Alerts fire at 50%, 80% and 100%."
  type        = number
  default     = 50
}

variable "budget_alert_email" {
  description = "Where budget alerts are sent."
  type        = string
}

variable "github_repository" {
  description = "owner/name allowed to assume the CI deploy role through GitHub OIDC."
  type        = string
  default     = "aymen-nasri/cloudshield"
}
