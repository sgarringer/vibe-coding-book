# ============================================
# COMMON VARIABLES
# ============================================

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Application name (used for resource naming)"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.app_name))
    error_message = "App name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "alb_arn" {
  description = "Application Load Balancer ARN to associate with WAF"
  type        = string
  
  validation {
    condition     = can(regex("^arn:aws:elasticloadbalancing:", var.alb_arn))
    error_message = "Must be a valid ALB ARN."
  }
}

variable "rate_limit_login" {
  description = "Rate limit for login endpoint (requests per 5 minutes per IP)"
  type        = number
  default     = 100
  
  validation {
    condition     = var.rate_limit_login >= 10 && var.rate_limit_login <= 10000
    error_message = "Rate limit must be between 10 and 10000."
  }
}

variable "rate_limit_api" {
  description = "Rate limit for API endpoints (requests per 5 minutes per IP)"
  type        = number
  default     = 2000
  
  validation {
    condition     = var.rate_limit_api >= 100 && var.rate_limit_api <= 20000
    error_message = "Rate limit must be between 100 and 20000."
  }
}

variable "enable_geo_blocking" {
  description = "Enable geographic blocking of requests"
  type        = bool
  default     = false
}

variable "blocked_countries" {
  description = "List of country codes to block (ISO 3166-1 alpha-2 format)"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for country in var.blocked_countries : can(regex("^[A-Z]{2}$", country))
    ])
    error_message = "Country codes must be 2-letter ISO 3166-1 alpha-2 codes (e.g., 'US', 'CN')."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain WAF logs in CloudWatch"
  type        = number
  default     = 30
  
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch Logs retention period."
  }
}

variable "alarm_threshold" {
  description = "Number of blocked requests to trigger CloudWatch alarm"
  type        = number
  default     = 100
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
