module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.16"

  name = "cloudshield-lab"
  cidr = "10.20.0.0/16"

  azs             = ["${var.region}a", "${var.region}b"]
  private_subnets = ["10.20.0.0/20", "10.20.16.0/20"]
  public_subnets  = ["10.20.128.0/24", "10.20.129.0/24"]

  # One NAT gateway keeps lab cost down; production would use one per AZ.
  enable_nat_gateway = true
  single_nat_gateway = true

  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_max_aggregation_interval    = 60
  flow_log_cloudwatch_log_group_retention_in_days = 7

  private_subnet_tags = { "kubernetes.io/role/internal-elb" = 1 }
  public_subnet_tags  = { "kubernetes.io/role/elb" = 1 }
}
