resource "random_id" "tenant_shared_bucket" {
  byte_length = 8
}

resource "aws_s3_bucket" "tenant_shared" {
  bucket = "${var.prefix}-tenant-shared-${random_id.tenant_shared_bucket.hex}"
}

resource "aws_s3_object" "tenant_a_file" {
  bucket  = aws_s3_bucket.tenant_shared.bucket
  key     = "tenant-a/data.txt"
  content = "Tenant A confidential data"
}

resource "aws_s3_object" "tenant_b_file" {
  bucket  = aws_s3_bucket.tenant_shared.bucket
  key     = "tenant-b/data.txt"
  content = "Tenant B confidential data"
}
