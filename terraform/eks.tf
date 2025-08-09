module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  name               = "${var.prefix}-self-mng"
  kubernetes_version = "1.33"

  addons = {
    coredns                = {}
    kube-proxy             = {}
    vpc-cni                = {}
    eks-pod-identity-agent = {}
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  endpoint_private_access      = true
  endpoint_public_access       = true
  endpoint_public_access_cidrs = ["0.0.0.0/0"]

  enable_cluster_creator_admin_permissions = true

  self_managed_node_groups = {
    default = {
      ami_type      = "AL2023_x86_64_STANDARD"
      ami_id        = "ami-0077d3b140075152e"
      instance_type = "m6i.large"

      min_size     = 1
      max_size     = 1
      desired_size = 1

      iam_role_additional_policies = {
        AmazonS3ReadOnlyAccess = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        AmazonEC2ReadOnlyAcces = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
      }

      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 1
        instance_metadata_tags      = "disabled"
      }
    }
  }

  tags = var.aws_tags
}
