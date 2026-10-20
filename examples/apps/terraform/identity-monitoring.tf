resource "aws_iam_role" "api" {
  count = var.provision_enabled ? 1 : 0
  name  = "atlas-synthetic-api"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole"
    Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
  }] })
}
resource "aws_iam_role_policy" "api" {
  count = var.provision_enabled ? 1 : 0
  role  = aws_iam_role.api[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.receipts[0].arn
  }] })
  # API role has no mail-send, secret-admin, backup-delete or IAM mutation permission.
}
resource "aws_sqs_queue" "receipts" {
  count                             = var.provision_enabled ? 1 : 0
  name                              = "atlas-synthetic-receipts"
  kms_master_key_id                  = aws_kms_key.app[0].arn
  message_retention_seconds         = 86400
  visibility_timeout_seconds        = 60
}
resource "aws_cloudwatch_log_group" "api" {
  count             = var.provision_enabled ? 1 : 0
  name              = "/atlas-synthetic/api"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.app[0].arn
}
resource "aws_sns_topic" "security" {
  count             = var.provision_enabled ? 1 : 0
  name              = "atlas-synthetic-security"
  kms_master_key_id = aws_kms_key.app[0].arn
}
resource "aws_budgets_budget" "usage" {
  count        = var.provision_enabled ? 1 : 0
  name         = "atlas-synthetic-budget"
  budget_type  = "COST"
  limit_amount = "25"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [aws_sns_topic.security[0].arn]
  }
  # Notification only: not a hard spending cap; escalation/stop is separately reviewed.
}
