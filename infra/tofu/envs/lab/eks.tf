module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.31"

  cluster_name    = var.cluster_name
  cluster_version = "1.31"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access = true
  enable_cluster_creator_admin_permissions = true

  # Control-plane audit logs feed the K8s audit evidence source (pods/exec, RBAC changes).
  cluster_enabled_log_types = ["audit", "authenticator"]

  cluster_addons = {
    vpc-cni = {
      most_recent = true
      # Native NetworkPolicy enforcement in the VPC CNI, required for quarantine.
      configuration_values = jsonencode({ enableNetworkPolicy = "true" })
    }
    coredns                = { most_recent = true }
    kube-proxy             = { most_recent = true }
    eks-pod-identity-agent = { most_recent = true }
  }

  eks_managed_node_groups = {
    lab = {
      instance_types = ["t3.medium"]
      capacity_type  = "SPOT"
      min_size       = 2
      max_size       = 3
      desired_size   = 2
    }
  }
}

# Investigator: read-only AWS context for enrichment.
data "aws_iam_policy_document" "pod_identity_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "investigator" {
  name               = "cloudshield-lab-investigator"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_trust.json
}

data "aws_iam_policy_document" "investigator" {
  statement {
    sid = "ReadOnlyContext"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "eks:DescribeCluster",
      "eks:ListPodIdentityAssociations",
      "eks:DescribePodIdentityAssociation",
      "iam:GetRole",
      "iam:ListAttachedRolePolicies",
      "iam:GetPolicyVersion",
      "cloudtrail:LookupEvents",
      "guardduty:GetFindings",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "ReadFindingsQueue"
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    resources = [aws_sqs_queue.findings.arn]
  }
  statement {
    sid       = "WriteRawEvidenceOnly"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/raw/*"]
  }
  statement {
    sid       = "EncryptEvidence"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
    resources = [aws_kms_key.evidence.arn]
  }
  statement {
    sid       = "InvokeInvestigatorModel"
    actions   = ["bedrock:InvokeModel", "bedrock:ApplyGuardrail"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "investigator" {
  role   = aws_iam_role.investigator.id
  policy = data.aws_iam_policy_document.investigator.json
}

resource "aws_eks_pod_identity_association" "investigator" {
  cluster_name    = module.eks.cluster_name
  namespace       = "cloudshield"
  service_account = "cloudshield-investigator"
  role_arn        = aws_iam_role.investigator.arn
}
