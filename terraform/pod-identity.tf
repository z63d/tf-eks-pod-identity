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
      "*" # "*" で全てのカスタマーRoleを対象にできる
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

# =====================================
# Multi-Tenant ABAC Demo - tenant isolation
# =====================================

data "aws_iam_policy_document" "tenant_abac" {
  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.tenant_shared.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/kubernetes-service-account"
      values   = ["tenant-a-app"]
    }
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["tenant-a/*"]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
    resources = ["${aws_s3_bucket.tenant_shared.arn}/tenant-a/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/kubernetes-service-account"
      values   = ["tenant-a-app"]
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.tenant_shared.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/kubernetes-service-account"
      values   = ["tenant-b-app"]
    }
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["tenant-b/*"]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
    resources = ["${aws_s3_bucket.tenant_shared.arn}/tenant-b/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/kubernetes-service-account"
      values   = ["tenant-b-app"]
    }
  }
}

resource "aws_iam_policy" "tenant_abac" {
  name        = "${var.prefix}-tenant-abac-policy"
  description = "Multi-tenant ABAC policy"
  policy      = data.aws_iam_policy_document.tenant_abac.json
}

resource "aws_iam_role" "tenant_shared" {
  name               = "${var.prefix}-tenant-shared"
  assume_role_policy = data.aws_iam_policy_document.trust_pod_identity.json
}

resource "aws_iam_role_policy_attachment" "tenant_abac_2_tenant_shared" {
  role       = aws_iam_role.tenant_shared.name
  policy_arn = aws_iam_policy.tenant_abac.arn
}

resource "aws_eks_pod_identity_association" "tenant_a" {
  cluster_name    = module.eks.cluster_name
  namespace       = "default"
  service_account = "tenant-a-app"
  role_arn        = aws_iam_role.tenant_shared.arn
}

resource "aws_eks_pod_identity_association" "tenant_b" {
  cluster_name    = module.eks.cluster_name
  namespace       = "default"
  service_account = "tenant-b-app"
  role_arn        = aws_iam_role.tenant_shared.arn
}

# =====================================
# ABAC Demo - Secrets Manager
# =====================================

resource "aws_secretsmanager_secret" "app_secret" {
  name                    = "${var.prefix}-app-secret"
  description             = "Secret for EKS pod access"
  recovery_window_in_days = 7

  tags = {
    kubernetes-namespace = "secret-demo"
  }
}

resource "aws_secretsmanager_secret_version" "app_secret" {
  secret_id = aws_secretsmanager_secret.app_secret.id
  secret_string = jsonencode({
    username = "admin"
    password = "Password01234"
  })
}

data "aws_iam_policy_document" "secretsmanager_access" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "secretsmanager:ResourceTag/kubernetes-namespace"
      values   = ["$${aws:PrincipalTag/kubernetes-namespace}"]
    }
  }
}

resource "aws_iam_policy" "secretsmanager_access" {
  name        = "${var.prefix}-secretsmanager-access"
  description = "ABAC policy for Secrets Manager access"
  policy      = data.aws_iam_policy_document.secretsmanager_access.json
}

resource "aws_iam_role" "secret_app_sa" {
  name               = "${var.prefix}-secret-app-sa"
  assume_role_policy = data.aws_iam_policy_document.trust_pod_identity.json
}

resource "aws_iam_role_policy_attachment" "secretsmanager_access_2_secret_app_sa" {
  role       = aws_iam_role.secret_app_sa.name
  policy_arn = aws_iam_policy.secretsmanager_access.arn
}

resource "aws_eks_pod_identity_association" "secretsmgr_app" {
  cluster_name    = module.eks.cluster_name
  namespace       = "secret-demo"
  service_account = "secret-app"
  role_arn        = aws_iam_role.secret_app_sa.arn
}
