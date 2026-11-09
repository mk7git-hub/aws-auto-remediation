terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.70" }
    archive = { source = "hashicorp/archive", version = "~> 2.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "aws-auto-remediation", ManagedBy = "terraform", Owner = var.owner }
  }
}

data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

locals {
  name    = "s3-public-remediation"
  account = data.aws_caller_identity.me.account_id
}

# ---------- Alerts ----------
resource "aws_kms_key" "this" {
  description         = "${local.name} SNS, SQS and logs"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Root", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${local.account}:root" }, Action = "kms:*", Resource = "*" },
      { Sid       = "Services", Effect = "Allow",
        Principal = { Service = ["logs.${data.aws_region.current.name}.amazonaws.com", "events.amazonaws.com", "cloudwatch.amazonaws.com", "sns.amazonaws.com", "sqs.amazonaws.com"] },
      Action = ["kms:Encrypt*", "kms:Decrypt*", "kms:GenerateDataKey*", "kms:Describe*"], Resource = "*" }
    ]
  })
  #checkov:skip=CKV_AWS_109:Standard key policy root statement
  #checkov:skip=CKV_AWS_111:Standard key policy root statement
  #checkov:skip=CKV_AWS_356:Key policies use Resource "*" (the key itself)
}

resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-alerts"
  kms_master_key_id = aws_kms_key.this.arn
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = { StringEquals = { "aws:SourceAccount" = local.account } }
    }]
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.name}-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.this.arn
}

# ---------- Lambda ----------
data "archive_file" "zip" {
  type        = "zip"
  source_file = "${path.module}/../src/remediate_s3.py"
  output_path = "${path.module}/build/remediate_s3.zip"
}

resource "aws_iam_role" "fn" {
  name = "${local.name}-fn"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# Least privilege: only the calls the function makes.
resource "aws_iam_role_policy" "fn" {
  #checkov:skip=CKV_AWS_290:Only X-Ray telemetry uses Resource "*", which X-Ray requires
  #checkov:skip=CKV_AWS_355:Only X-Ray telemetry uses Resource "*", which X-Ray requires
  name = "remediate"
  role = aws_iam_role.fn.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "S3", Effect = "Allow", Action = ["s3:PutBucketPublicAccessBlock", "s3:GetBucketTagging"], Resource = "arn:aws:s3:::*" },
      { Sid = "Findings", Effect = "Allow", Action = ["securityhub:BatchUpdateFindings"], Resource = "arn:aws:securityhub:${data.aws_region.current.name}:${local.account}:hub/default" },
      { Sid = "Notify", Effect = "Allow", Action = ["sns:Publish"], Resource = aws_sns_topic.alerts.arn },
      { Sid = "Dlq", Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.dlq.arn },
      { Sid = "Kms", Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = aws_kms_key.this.arn },
      { Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.fn.arn}:*" },
      { Sid = "Xray", Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], Resource = "*" }
    ]
  })
}

resource "aws_cloudwatch_log_group" "fn" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.this.arn
}

resource "aws_lambda_function" "fn" {
  function_name                  = local.name
  role                           = aws_iam_role.fn.arn
  runtime                        = "python3.12"
  handler                        = "remediate_s3.handler"
  filename                       = data.archive_file.zip.output_path
  source_code_hash               = data.archive_file.zip.output_base64sha256
  timeout                        = 30
  memory_size                    = 128
  reserved_concurrent_executions = 5
  kms_key_arn                    = aws_kms_key.this.arn

  environment {
    variables = { ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn, DRY_RUN = tostring(var.dry_run) }
  }
  dead_letter_config { target_arn = aws_sqs_queue.dlq.arn }
  tracing_config { mode = "Active" }

  #checkov:skip=CKV_AWS_117:Function calls only public AWS APIs; no VPC needed and no NAT cost
  #checkov:skip=CKV_AWS_272:Code signing is out of scope for a single-author lab
  depends_on = [aws_cloudwatch_log_group.fn]
}

# ---------- Triggers ----------
resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = "${local.name}-api-calls"
  description = "S3 API calls that can make a bucket public"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["DeleteBucketPublicAccessBlock", "PutBucketPolicy", "PutBucketAcl"]
    }
  })
}

resource "aws_cloudwatch_event_rule" "securityhub" {
  name        = "${local.name}-findings"
  description = "Failed Security Hub S3 public access controls"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance = { SecurityControlId = ["S3.2", "S3.3", "S3.8"], Status = ["FAILED"] }
        Workflow   = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "targets" {
  for_each = { api = aws_cloudwatch_event_rule.cloudtrail.name, findings = aws_cloudwatch_event_rule.securityhub.name }
  rule     = each.value
  arn      = aws_lambda_function.fn.arn
  retry_policy {
    maximum_retry_attempts       = 4
    maximum_event_age_in_seconds = 3600
  }
}

resource "aws_lambda_permission" "events" {
  for_each      = { api = aws_cloudwatch_event_rule.cloudtrail.arn, findings = aws_cloudwatch_event_rule.securityhub.arn }
  statement_id  = "events-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn.function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value
}

# ---------- Observability ----------
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${local.name}-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.fn.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${local.name}-dlq-not-empty"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = local.name
  dashboard_body = jsonencode({
    widgets = [
      { type = "metric", x = 0, y = 0, width = 12, height = 6, properties = {
        title = "Remediations (invocations) and errors", region = data.aws_region.current.name, stat = "Sum", period = 300,
      metrics = [["AWS/Lambda", "Invocations", "FunctionName", local.name], [".", "Errors", ".", "."]] } },
      { type = "metric", x = 12, y = 0, width = 12, height = 6, properties = {
        title = "Time to remediate (Lambda duration, p95)", region = data.aws_region.current.name, stat = "p95", period = 300,
      metrics = [["AWS/Lambda", "Duration", "FunctionName", local.name]] } },
      { type = "log", x = 0, y = 6, width = 24, height = 6, properties = {
        title = "Latest actions", region = data.aws_region.current.name,
      query = "SOURCE '/aws/lambda/${local.name}' | fields @timestamp, @message | filter @message like /results/ | sort @timestamp desc | limit 20" } }
    ]
  })
}
