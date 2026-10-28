terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # State lives in a separate, versioned bucket created once by hand (see docs/adr/0004).
  backend "s3" {
    key          = "cloudshield/lab/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "cloudshield"
      Environment = "lab"
      ManagedBy   = "opentofu"
    }
  }
}
