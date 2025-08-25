output "application_customer_assume_role_test_commands" {
  description = "Test commands for application to customer assume role"
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

output "tenant_isolation_test_commands" {
  description = "Test commands for SaaS tenant isolation using kubernetes-service-account ABAC"
  value       = <<EOF
# SaaSテナント分離ABACテスト（kubernetes-service-accountタグベース）
# ABAC制御により各テナントは自分のディレクトリのみアクセス可能

# === Tenant A テスト ===
# kubectl exec -it deployment/tenant-a-app -- /bin/sh で実行

# 1. 現在の認証情報を確認
aws sts get-caller-identity

# 2. 自分のテナントディレクトリ一覧表示（成功）
aws s3 ls s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-a/

# 3. 自分のディレクトリからファイル取得（成功）
aws s3 cp s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-a/data.txt -

# 4. 自分のディレクトリにファイル作成（成功）
echo "New Tenant A file" > /tmp/new-file.txt
aws s3 cp /tmp/new-file.txt s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-a/new-file.txt

# 5. 他のテナントディレクトリ一覧表示（失敗：prefix制御により見えない）
aws s3 ls s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-b/
# → AccessDenied (s3:prefix条件によりListBucket拒否)

# 6. 他のテナントファイルアクセス（失敗：resource ARNによりアクセス拒否）
aws s3 cp s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-b/data.txt -
# → AccessDenied (resource制御によりGetObject拒否)

# === Tenant B テスト ===  
# kubectl exec -it deployment/tenant-b-app -- /bin/sh で実行

# 1. 現在の認証情報を確認  
aws sts get-caller-identity

# 2. 自分のテナントディレクトリアクセス（成功）
aws s3 ls s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-b/
aws s3 cp s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-b/data.txt -

# 3. 他のテナントディレクトリアクセス（失敗）
aws s3 ls s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-a/
aws s3 cp s3://${aws_s3_bucket.tenant_shared.bucket}/tenant-a/data.txt -
# → AccessDenied (ABAC制御により完全分離)

# === ABAC制御の仕組み ===
# - ListBucket: s3:prefix条件でディレクトリレベル分離
# - GetObject/PutObject/DeleteObject: resource ARNとkubernetes-service-accountタグで制御
# - 各テナントは自分専用ディレクトリのみアクセス可能
EOF
}

output "abac_demo_test_commands" {
  description = "Test commands for ABAC demo using Secrets Manager"
  value       = <<EOF
# ABAC Demo - Secrets Manager Access Control
# ABAC制御によりnamespace tagが一致するPodのみがsecretにアクセス可能

# === Secret Demo Pod テスト ===
# kubectl exec -it deployment/secrets-app -n secret-demo -- /bin/sh で実行

# 1. 現在の認証情報を確認
aws sts get-caller-identity

# 2. ABAC制御されたsecretの取得（成功：namespace tagが一致）
aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.app_secret.name} --region ap-northeast-1

# 3. secretの詳細情報を確認（成功：DescribeSecret権限あり）
aws secretsmanager describe-secret --secret-id ${aws_secretsmanager_secret.app_secret.name} --region ap-northeast-1

# === 他のnamespaceからのアクセステスト（失敗例） ===
# 異なるnamespaceのPodからアクセスした場合はAccessDenied

# kubernetes-namespaceタグが "secret-demo" 以外のPodからアクセス
# → AccessDenied (ABAC制御により拒否)

# === ABAC制御の仕組み ===
# - Secrets Manager resource tag: kubernetes-namespace = "secret-demo"  
# - Pod principal tag: kubernetes-namespace = "secret-demo"
# - 条件: secretsmanager:ResourceTag/kubernetes-namespace == aws:PrincipalTag/kubernetes-namespace
# - 結果: タグが一致するPodのみアクセス許可
EOF
}
