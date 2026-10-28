# GuardDuty -> EventBridge -> SQS (+ DLQ) -> CloudShield SQS consumer.

resource "aws_guardduty_detector" "lab" {
  enable = true
}

resource "aws_guardduty_detector_feature" "eks_runtime" {
  detector_id = aws_guardduty_detector.lab.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
}

resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  detector_id = aws_guardduty_detector.lab.id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

resource "aws_sqs_queue" "findings_dlq" {
  name                      = "cloudshield-lab-findings-dlq"
  message_retention_seconds = 1209600 # 14 days to investigate failures
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "findings" {
  name                       = "cloudshield-lab-findings"
  visibility_timeout_seconds = 60
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.findings_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "cloudshield-guardduty-findings"
  description = "Route GuardDuty findings to CloudShield"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "to_sqs" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = aws_sqs_queue.findings.arn
}

data "aws_iam_policy_document" "eventbridge_to_sqs" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.findings.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "findings" {
  queue_url = aws_sqs_queue.findings.id
  policy    = data.aws_iam_policy_document.eventbridge_to_sqs.json
}

# A growing dead-letter queue means evidence is not being processed: alarm on it.
resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  alarm_name          = "cloudshield-lab-findings-dlq-not-empty"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.findings_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
