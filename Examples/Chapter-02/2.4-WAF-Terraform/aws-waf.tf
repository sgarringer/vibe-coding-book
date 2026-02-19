# ============================================
# AWS WAF TERRAFORM CONFIGURATION
# ============================================
# Referenced in: Vibe-Coded App Security Framework
# Chapter 2.4.2: WAF Deployment
#
# This configuration creates:
# - AWS WAFv2 Web ACL
# - AWS Managed Rule Groups
# - Custom rate limiting rules
# - Association with Application Load Balancer
# ============================================

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ============================================
# VARIABLES
# ============================================

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "yourapp"
}

variable "alb_arn" {
  description = "Application Load Balancer ARN"
  type        = string
}

variable "rate_limit_login" {
  description = "Rate limit for login endpoint (requests per 5 minutes)"
  type        = number
  default     = 100
}

variable "rate_limit_api" {
  description = "Rate limit for API endpoints (requests per 5 minutes)"
  type        = number
  default     = 2000
}

variable "enable_geo_blocking" {
  description = "Enable geo-blocking"
  type        = bool
  default     = false
}

variable "blocked_countries" {
  description = "List of country codes to block (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = []  # Example: ["CN", "RU", "KP"]
}

# ============================================
# WAF WEB ACL
# ============================================

resource "aws_wafv2_web_acl" "main" {
  name        = "${var.app_name}-waf"
  description = "WAF for ${var.app_name}"
  scope       = "REGIONAL"  # Use "CLOUDFRONT" for CloudFront distributions

  default_action {
    allow {}
  }

  # ============================================
  # RULE 1: AWS MANAGED CORE RULE SET
  # ============================================
  # OWASP Top 10 protection
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # Exclude rules that cause false positives (optional)
        # excluded_rule {
        #   name = "SizeRestrictions_BODY"
        # }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # ============================================
  # RULE 2: AWS MANAGED KNOWN BAD INPUTS
  # ============================================
  # Known malicious patterns
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # ============================================
  # RULE 3: AWS MANAGED SQL INJECTION
  # ============================================
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # ============================================
  # RULE 4: RATE LIMITING - LOGIN ENDPOINT
  # ============================================
  rule {
    name     = "RateLimitLogin"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_login
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/login"
            positional_constraint = "CONTAINS"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitLoginMetric"
      sampled_requests_enabled   = true
    }
  }

  # ============================================
  # RULE 5: RATE LIMITING - API ENDPOINTS
  # ============================================
  rule {
    name     = "RateLimitAPI"
    priority = 11

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_api
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/api/"
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitAPIMetric"
      sampled_requests_enabled   = true
    }
  }

  # ============================================
  # RULE 6: GEO-BLOCKING (OPTIONAL)
  # ============================================
  dynamic "rule" {
    for_each = var.enable_geo_blocking ? [1] : []

    content {
      name     = "GeoBlocking"
      priority = 20

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.blocked_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "GeoBlockingMetric"
        sampled_requests_enabled   = true
      }
    }
  }

  # ============================================
  # RULE 7: BLOCK COMMON ATTACK PATTERNS
  # ============================================
  rule {
    name     = "BlockCommonAttacks"
    priority = 30

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          # Block requests with "../" (path traversal)
          byte_match_statement {
            search_string         = "../"
            positional_constraint = "CONTAINS"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
          }
        }

        statement {
          # Block requests with "etc/passwd"
          byte_match_statement {
            search_string         = "etc/passwd"
            positional_constraint = "CONTAINS"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          # Block requests with "<script>" (XSS)
          byte_match_statement {
            search_string         = "<script>"
            positional_constraint = "CONTAINS"

            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockCommonAttacksMetric"
      sampled_requests_enabled   = true
    }
  }

  # ============================================
  # VISIBILITY CONFIG
  # ============================================
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.app_name}-waf-metric"
    sampled_requests_enabled   = true
  }

  tags = {
    Name        = "${var.app_name}-waf"
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

# ============================================
# ASSOCIATE WAF WITH ALB
# ============================================

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# ============================================
# CLOUDWATCH LOG GROUP
# ============================================

resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "/aws/waf/${var.app_name}"
  retention_in_days = 30

  tags = {
    Name        = "${var.app_name}-waf-logs"
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

# ============================================
# WAF LOGGING CONFIGURATION
# ============================================

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

# ============================================
# CLOUDWATCH ALARMS
# ============================================

resource "aws_cloudwatch_metric_alarm" "blocked_requests" {
  alarm_name          = "${var.app_name}-waf-blocked-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "This metric monitors WAF blocked requests"
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Region = var.aws_region
    Rule   = "ALL"
  }

  tags = {
    Name        = "${var.app_name}-waf-alarm"
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

# ============================================
# OUTPUTS
# ============================================

output "waf_web_acl_id" {
  description = "WAF Web ACL ID"
  value       = aws_wafv2_web_acl.main.id
}

output "waf_web_acl_arn" {
  description = "WAF Web ACL ARN"
  value       = aws_wafv2_web_acl.main.arn
}

output "waf_log_group_name" {
  description = "CloudWatch Log Group name for WAF logs"
  value       = aws_cloudwatch_log_group.waf_logs.name
}

output "waf_dashboard_url" {
  description = "AWS Console URL for WAF dashboard"
  value       = "https://console.aws.amazon.com/wafv2/homev2/web-acl/${aws_wafv2_web_acl.main.name}/${aws_wafv2_web_acl.main.id}/overview?region=${var.aws_region}"
}
