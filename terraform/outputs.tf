output "multi_tenant_test_commands" {
  description = "Test commands for multi-tenant assume role"
  value       = <<EOF
# 現在のアプリケーションRole情報を確認
aws sts get-caller-identity

# カスタマーRoleをassume role (External IDを使用)
CREDS=$(aws sts assume-role \
  --role-arn ${aws_iam_role.customer.arn} \
  --role-session-name "customer-session" \
  --external-id "external-id-${random_id.customer_s3_bucket.hex}" \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
  --output text)

# 環境変数に設定
export AWS_ACCESS_KEY_ID=$(echo $CREDS | awk '{print $1}')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | awk '{print $2}')
export AWS_SESSION_TOKEN=$(echo $CREDS | awk '{print $3}')

# カスタマーRoleで動作確認
aws sts get-caller-identity
aws s3 ls s3://${aws_s3_bucket.customer.bucket}/
aws s3 cp s3://${aws_s3_bucket.customer.bucket}/test.txt -
EOF
}
