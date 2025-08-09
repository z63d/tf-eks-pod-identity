data "aws_iam_policy_document" "trust_pod_identity" {
  # Assume role for EC2 instances
  # statement {
  #   effect = "Allow"
  #   principals {
  #     type        = "Service"
  #     identifiers = ["ec2.amazonaws.com"]
  #   }
  #   actions = [
  #     "sts:AssumeRole"
  #   ]
  # }

  # IRSA
  # statement {
  #   effect = "Allow"
  #   principals {
  #     type        = "Federated"
  #     identifiers = [module.eks.oidc_provider_arn]
  #   }
  #   actions = ["sts:AssumeRoleWithWebIdentity"]
  #   condition {
  #     test     = "StringEquals"
  #     variable = "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub"
  #     values   = ["system:serviceaccount:default:aws-cli-0"]
  #   }
  #   condition {
  #     test     = "StringEquals"
  #     variable = "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:aud"
  #     values   = ["sts.amazonaws.com"]
  #   }
  # }

  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
    actions = [
      "sts:AssumeRole",
      "sts:TagSession"
    ]
  }
}

# =====================================
# aws-cli-0
# =====================================

data "aws_iam_policy_document" "s3_access" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListAllMyBuckets"
    ]
    resources = [
      "arn:aws:s3:::*",
      "arn:aws:s3:::*/*"
    ]
  }
}

resource "aws_iam_policy" "s3_access" {
  name        = "${var.prefix}-s3-access"
  description = "IAM policy for S3 access"
  policy      = data.aws_iam_policy_document.s3_access.json
}

resource "aws_iam_role" "aws_cli_0_sa" {
  name               = "${var.prefix}-aws-cli-0-sa"
  assume_role_policy = data.aws_iam_policy_document.trust_pod_identity.json
}

resource "aws_iam_role_policy_attachment" "s3_access_2_aws_cli_0_sa" {
  role       = aws_iam_role.aws_cli_0_sa.name
  policy_arn = aws_iam_policy.s3_access.arn
}

resource "aws_eks_pod_identity_association" "aws_cli_0" {
  cluster_name    = module.eks.cluster_name
  namespace       = "default"
  service_account = "aws-cli-0"
  role_arn        = aws_iam_role.aws_cli_0_sa.arn
}

# =====================================
# aws-cli-1
# =====================================

data "aws_iam_policy_document" "ec2_access" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeImages",
      "ec2:DescribeKeyPairs",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ec2_access" {
  name        = "${var.prefix}-ec2-access"
  description = "IAM policy for EKS to access EC2"
  policy      = data.aws_iam_policy_document.ec2_access.json
}

resource "aws_iam_role" "aws_cli_1_sa" {
  name               = "${var.prefix}-aws-cli-1-sa"
  assume_role_policy = data.aws_iam_policy_document.trust_pod_identity.json
}

resource "aws_iam_role_policy_attachment" "ec2_access_2_aws_cli_1_sa" {
  role       = aws_iam_role.aws_cli_1_sa.name
  policy_arn = aws_iam_policy.ec2_access.arn
}

resource "aws_eks_pod_identity_association" "aws_cli_1" {
  cluster_name    = module.eks.cluster_name
  namespace       = "default"
  service_account = "aws-cli-1"
  role_arn        = aws_iam_role.aws_cli_1_sa.arn
}

# =====================================
# アプリケーション → カスタマーRole の多段Assume Role構成
# =====================================

data "aws_iam_policy_document" "assume_role_to_customer_role_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole"
    ]
    resources = [
      aws_iam_role.customer.arn # "*" で全てのカスタマーRoleを対象にできる
    ]
  }
}

resource "aws_iam_policy" "assume_role_to_customer_role_permissions" {
  name        = "${var.prefix}-assume-role-to-customer-role-permissions"
  description = "Allows application to assume customer roles"
  policy      = data.aws_iam_policy_document.assume_role_to_customer_role_permissions.json
}

resource "aws_iam_role" "application_sa" {
  name               = "${var.prefix}-application-sa"
  assume_role_policy = data.aws_iam_policy_document.trust_pod_identity.json
}

resource "aws_iam_role_policy_attachment" "assume_role_to_customer_role_permissions_2_application_sa" {
  role       = aws_iam_role.application_sa.name
  policy_arn = aws_iam_policy.assume_role_to_customer_role_permissions.arn
}

resource "aws_eks_pod_identity_association" "application" {
  cluster_name    = module.eks.cluster_name
  namespace       = "default"
  service_account = "application"
  role_arn        = aws_iam_role.application_sa.arn

  disable_session_tags = false # セッションタグを無効化することで、Assume Role時に不要なタグが付与されないようにする
}
