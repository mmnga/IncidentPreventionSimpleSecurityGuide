resource "aws_kms_key" "app" {
  count                   = var.provision_enabled ? 1 : 0
  description             = "Atlas synthetic data separation"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket" "audit" {
  count               = var.provision_enabled ? 1 : 0
  bucket_prefix       = "atlas-synthetic-audit-"
  object_lock_enabled = true
  force_destroy       = false
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket_public_access_block" "audit" {
  count                   = var.provision_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.audit[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "audit" {
  count  = var.provision_enabled ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  count  = var.provision_enabled ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.app[0].arn
    }
  }
}
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  count  = var.provision_enabled ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit]
}
resource "aws_backup_vault" "isolated" {
  count       = var.provision_enabled ? 1 : 0
  name        = "atlas-synthetic-backup"
  kms_key_arn = aws_kms_key.app[0].arn
  lifecycle { prevent_destroy = true }
}
resource "aws_backup_plan" "daily" {
  count = var.provision_enabled ? 1 : 0
  name  = "atlas-synthetic-daily"
  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.isolated[0].name
    schedule          = "cron(0 3 * * ? *)"
    lifecycle { delete_after = 35 }
  }
}
