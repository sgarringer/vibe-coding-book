# ============================================
# TERRAFORM OUTPUTS
# ============================================

output "waf_web_acl_id" {
  description = "The ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.id
}

output "waf_web_acl_arn" {
  description = "The ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "waf_web_acl_name" {
  description = "The name of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.name
}

output "waf_log_group_name" {
  description = "CloudWatch Log Group name for WAF logs"
  value       = aws_cloudwatch_log_group.waf_logs.name
}

output "waf_log_group_arn" {
  description = "CloudWatch Log Group ARN for WAF logs"
  value       = aws_cloudwatch_log_group.waf_logs.arn
}

output "waf_dashboard_url" {
  description = "AWS Console URL for WAF dashboard"
  value       = "https://console.aws.amazon.com/wafv2/homev2/web-acl/${aws_wafv2_web_acl.main.name}/${aws_wafv2_web_acl.main.id}/overview?region=${var.aws_region}"
}

output "cloudwatch_logs_url" {
  description = "AWS Console URL for CloudWatch Logs"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#logsV2:log-groups/log-group/${replace(aws_cloudwatch_log_group.waf_logs.name, "/", "$252F")}"
}

output "alarm_arn" {
  description = "CloudWatch Alarm ARN for blocked requests"
  value       = aws_cloudwatch_metric_alarm.blocked_requests.arn
}

output "deployment_summary" {
  description = "Summary of deployed resources"
  value = {
    waf_name          = aws_wafv2_web_acl.main.name
    region            = var.aws_region
    alb_arn           = var.alb_arn
    rate_limit_login  = var.rate_limit_login
    rate_limit_api    = var.rate_limit_api
    geo_blocking      = var.enable_geo_blocking
    blocked_countries = var.blocked_countries
  }
}
