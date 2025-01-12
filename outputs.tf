output "guardduty_findings_critical_sns_topic" {
  description = "The ARN of the SNS topic for critical GuardDuty findings"
  value       = var.enabled ? aws_sns_topic.guardduty_findings_critical[0].arn : null
}

output "guardduty_findings_info_sns_topic" {
  description = "The ARN of the SNS topic for info GuardDuty findings"
  value       = var.enabled ? aws_sns_topic.guardduty_findings_info[0].arn : null
}

output "guardduty_findings_warning_sns_topic" {
  description = "The ARN of the SNS topic for warning GuardDuty findings"
  value       = var.enabled ? aws_sns_topic.guardduty_findings_warning[0].arn : null
}
