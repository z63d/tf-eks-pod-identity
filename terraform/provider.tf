terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.2.0"
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
