# This can easily be done with a for_each, but it is made this way to keep the variable as a simple boolean
resource "aws_sns_topic" "guardduty_findings_info" {
  count             = var.enabled ? 1 : 0
  kms_master_key_id = aws_kms_key.this[0].key_id
  name              = "${var.name}-findings-info"
  policy            = data.aws_iam_policy_document.sns_access_policy.json

  tags = module.this.tags
}

resource "aws_sns_topic_subscription" "info_email_subscription" {
  count     = var.enabled ? 1 : 0
  topic_arn = aws_sns_topic.guardduty_findings_info[0].arn
  protocol  = "email"
  endpoint  = var.sns_subscription_email
}

resource "aws_sns_topic" "guardduty_findings_warning" {
  count             = var.enabled ? 1 : 0
  kms_master_key_id = aws_kms_key.this[0].key_id
  name              = "${var.name}-findings-warning"
  policy            = data.aws_iam_policy_document.sns_access_policy.json

  tags = module.this.tags
}

resource "aws_sns_topic_subscription" "warnings_email_subscription" {
  count     = var.enabled ? 1 : 0
  topic_arn = aws_sns_topic.guardduty_findings_warning[0].arn
  protocol  = "email"
  endpoint  = var.sns_subscription_email
}

resource "aws_sns_topic" "guardduty_findings_critical" {
  count             = var.enabled ? 1 : 0
  kms_master_key_id = aws_kms_key.this[0].key_id
  name              = "${var.name}-findings-critical"
  policy            = data.aws_iam_policy_document.sns_access_policy.json

  tags = module.this.tags
}

resource "aws_sns_topic_subscription" "critical_email_subscription" {
  count     = var.enabled ? 1 : 0
  topic_arn = aws_sns_topic.guardduty_findings_critical[0].arn
  protocol  = "email"
  endpoint  = var.sns_subscription_email
}

resource "aws_cloudwatch_event_rule" "info" {
  count         = var.enabled ? 1 : 0
  name          = "${var.name}-finding-info-events"
  event_pattern = file("${path.module}/event-pattern-info.json")

  tags = module.this.tags
}

resource "aws_cloudwatch_event_rule" "warning" {
  count         = var.enabled ? 1 : 0
  name          = "${var.name}-finding-warning-events"
  event_pattern = file("${path.module}/event-pattern-warning.json")

  tags = module.this.tags
}

resource "aws_cloudwatch_event_rule" "critical" {
  count         = var.enabled ? 1 : 0
  name          = "${var.name}-finding-critical-events"
  event_pattern = file("${path.module}/event-pattern-critical.json")

  tags = module.this.tags
}

resource "aws_cloudwatch_event_target" "info" {
  count     = var.enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.info[0].name
  target_id = "info"
  arn       = aws_sns_topic.guardduty_findings_info[0].arn
}

resource "aws_cloudwatch_event_target" "warning" {
  count     = var.enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.warning[0].name
  target_id = "warning"
  arn       = aws_sns_topic.guardduty_findings_warning[0].arn
}

resource "aws_cloudwatch_event_target" "critical" {
  count     = var.enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.critical[0].name
  target_id = "critical"
  arn       = aws_sns_topic.guardduty_findings_critical[0].arn
}

resource "aws_kms_key" "this" {
  count               = var.enabled ? 1 : 0
  description         = "Key used to encrypt the GuardDuty findings SNS topics"
  policy              = data.aws_iam_policy_document.kms_key_policy.json
  enable_key_rotation = true

  tags = module.this.tags
}

resource "aws_kms_alias" "this" {
  count         = var.enabled ? 1 : 0
  name          = "alias/guard-duty-findings-SNS-topics"
  target_key_id = aws_kms_key.this[0].key_id
}

### Supporting Resources
data "aws_iam_policy_document" "sns_access_policy" {
  version = "2008-10-17"
  statement {
    sid    = "__default_statement_ID"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes",
      "SNS:AddPermission",
      "SNS:RemovePermission",
      "SNS:DeleteTopic",
      "SNS:Subscribe",
      "SNS:ListSubscriptionsByTopic",
      "SNS:Publish"
    ]
    resources = ["arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:guardduty-findings-*"]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid    = "TrustCWEToPublishEvents"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions = [
      "SNS:Publish"
    ]
    resources = ["arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:guardduty-findings-*"]
  }

}

data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid    = "Grant KMS key rights to the root of this AWS account: ${data.aws_caller_identity.current.account_id}."
    effect = "Allow"
    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
      type        = "AWS"
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
  statement {
    sid    = "Grant necessary permissions for use by the Events service in publishing SNS messages."
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt"
    ]
    resources = ["*"]
  }
  statement {
    sid    = "Grant necessary permissions for use by the SNS service in publishing SNS messages."
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt"
    ]
    resources = ["*"]
  }
}
