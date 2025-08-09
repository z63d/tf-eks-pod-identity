# =====================================
# S3
# =====================================

resource "random_id" "customer_s3_bucket" {
  byte_length = 8
}

resource "aws_s3_bucket" "customer" {
  bucket = "${var.prefix}-customer-${random_id.customer_s3_bucket.hex}"
}

resource "aws_s3_object" "customer_test_file" {
  bucket  = aws_s3_bucket.customer.bucket
  key     = "test.txt"
  content = "customer test file content"
}

# =====================================
# IAM
# =====================================

data "aws_iam_policy_document" "trust_application_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.application_sa.arn]
    }
    actions = [
      "sts:AssumeRole"
    ]
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["external-id-${random_id.customer_s3_bucket.hex}"] # 実際の環境ではテナントごとに異なるID
    }
  }
  # aws_eks_pod_identity_association の `disable_session_tags = false` の場合、以下のセクションが必要
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.application_sa.arn]
    }
    actions = [
      "sts:TagSession"
    ]
  }
}

data "aws_iam_policy_document" "customer_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.customer.arn,
      "${aws_s3_bucket.customer.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "customer_permissions" {
  name        = "${var.prefix}-customer-permissions"
  description = "IAM policy for customer-specific resource access"
  policy      = data.aws_iam_policy_document.customer_permissions.json
}

resource "aws_iam_role" "customer" {
  name               = "${var.prefix}-customer"
  assume_role_policy = data.aws_iam_policy_document.trust_application_assume_role.json
}

resource "aws_iam_role_policy_attachment" "customer_permissions_2_customer" {
  role       = aws_iam_role.customer.name
  policy_arn = aws_iam_policy.customer_permissions.arn
}
