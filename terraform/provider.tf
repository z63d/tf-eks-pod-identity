terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.95, < 6.0.0"
    }
  }
}

provider "aws" {
  profile = var.aws_profile
  region  = var.region
  default_tags {
    tags = var.aws_tags
  }
}
