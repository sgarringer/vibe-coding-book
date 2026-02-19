# ============================================
# CLOUDFLARE WAF TERRAFORM CONFIGURATION
# ============================================
# Referenced in: Vibe-Coded App Security Framework
# Chapter 2.4.2: WAF Deployment
#
# This configuration creates:
# - Cloudflare WAF rules
# - Rate limiting rules
# - Custom firewall rules
# - Page rules for security
# ============================================

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ============================================
# VARIABLES
# ============================================

variable "cloudflare_api_token" {
  description = "Cloudflare API token"
  type        = string
  sensitive   = true
}

variable "zone_id" {
  description = "Cloudflare Zone ID"
  type        = string
}

variable "domain" {
  description = "Domain name"
  type        = string
  default     = "yourapp.com"
}

variable "rate_limit_login_threshold" {
  description = "Rate limit threshold for login endpoint"
  type        = number
  default     = 10
}

variable "rate_limit_api_threshold" {
  description = "Rate limit threshold for API endpoints"
  type        = number
  default     = 100
}

variable "enable_bot_fight_mode" {
  description = "Enable Bot Fight Mode (free plan)"
  type        = bool
  default     = true
}

variable "security_level" {
  description = "Security level: off, essentially_off, low, medium, high, under_attack"
  type        = string
  default     = "medium"
  
  validation {
    condition     = contains(["off", "essentially_off", "low", "medium", "high", "under_attack"], var.security_level)
    error_message = "Security level must be one of: off, essentially_off, low, medium, high, under_attack."
  }
}

variable "blocked_countries" {
  description = "List of country codes to block (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = []
}

# ============================================
# ZONE SETTINGS
# ============================================

# Get zone information
data "cloudflare_zone" "main" {
  zone_id = var.zone_id
}

# ============================================
# SSL/TLS SETTINGS
# ============================================

resource "cloudflare_zone_settings_override" "main" {
  zone_id = var.zone_id

  settings {
    # SSL/TLS
    ssl                      = "strict"
    always_use_https         = "on"
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    automatic_https_rewrites = "on"

    # Security
    security_level           = var.security_level
    challenge_ttl            = 1800
    browser_check            = "on"
    hotlink_protection       = "on"
    
    # Performance
    http2                    = "on"
    http3                    = "on"
    zero_rtt                 = "on"
    
    # Bot Management (Free)
    brotli                   = "on"
  }
}

# ============================================
# FIREWALL RULES
# ============================================

# Rule 1: Block SQL Injection Patterns
resource "cloudflare_filter" "block_sql_injection" {
  zone_id     = var.zone_id
  description = "Block SQL injection patterns"
  expression  = "(http.request.uri.query contains \"' OR '1'='1\" or http.request.uri.query contains \"UNION SELECT\" or http.request.uri.query contains \"DROP TABLE\" or http.request.uri.query contains \"'; DROP\")"
}

resource "cloudflare_firewall_rule" "block_sql_injection" {
  zone_id     = var.zone_id
  description = "Block SQL injection attempts"
  filter_id   = cloudflare_filter.block_sql_injection.id
  action      = "block"
  priority    = 1
}

# Rule 2: Block XSS Patterns
resource "cloudflare_filter" "block_xss" {
  zone_id     = var.zone_id
  description = "Block XSS patterns"
  expression  = "(http.request.uri.query contains \"<script>\" or http.request.uri.query contains \"javascript:\" or http.request.uri.query contains \"onerror=\" or http.request.uri.query contains \"<iframe\")"
}

resource "cloudflare_firewall_rule" "block_xss" {
  zone_id     = var.zone_id
  description = "Block XSS attempts"
  filter_id   = cloudflare_filter.block_xss.id
  action      = "block"
  priority    = 2
}

# Rule 3: Block Path Traversal
resource "cloudflare_filter" "block_path_traversal" {
  zone_id     = var.zone_id
  description = "Block path traversal patterns"
  expression  = "(http.request.uri.path contains \"../\" or http.request.uri.path contains \"..\\\\\" or http.request.uri.path contains \"/etc/passwd\")"
}

resource "cloudflare_firewall_rule" "block_path_traversal" {
  zone_id     = var.zone_id
  description = "Block path traversal attempts"
  filter_id   = cloudflare_filter.block_path_traversal.id
  action      = "block"
  priority    = 3
}

# Rule 4: Block Known Bad User Agents
resource "cloudflare_filter" "block_bad_user_agents" {
  zone_id     = var.zone_id
  description = "Block known bad user agents"
  expression  = "(http.user_agent contains \"sqlmap\" or http.user_agent contains \"nikto\" or http.user_agent contains \"nmap\" or http.user_agent contains \"masscan\" or http.user_agent contains \"acunetix\")"
}

resource "cloudflare_firewall_rule" "block_bad_user_agents" {
  zone_id     = var.zone_id
  description = "Block known attack tools"
  filter_id   = cloudflare_filter.block_bad_user_agents.id
  action      = "block"
  priority    = 4
}

# Rule 5: Challenge Suspicious Requests
resource "cloudflare_filter" "challenge_suspicious" {
  zone_id     = var.zone_id
  description = "Challenge suspicious requests"
  expression  = "(cf.threat_score gt 10)"
}

resource "cloudflare_firewall_rule" "challenge_suspicious" {
  zone_id     = var.zone_id
  description = "Challenge requests with threat score > 10"
  filter_id   = cloudflare_filter.challenge_suspicious.id
  action      = "managed_challenge"
  priority    = 5
}

# Rule 6: Geo-Blocking (if enabled)
resource "cloudflare_filter" "geo_blocking" {
  count       = length(var.blocked_countries) > 0 ? 1 : 0
  zone_id     = var.zone_id
  description = "Block specific countries"
  expression  = "(ip.geoip.country in {${join(" ", formatlist("\"%s\"", var.blocked_countries))}})"
}

resource "cloudflare_firewall_rule" "geo_blocking" {
  count       = length(var.blocked_countries) > 0 ? 1 : 0
  zone_id     = var.zone_id
  description = "Block traffic from specific countries"
  filter_id   = cloudflare_filter.geo_blocking[0].id
  action      = "block"
  priority    = 10
}

# ============================================
# RATE LIMITING RULES
# ============================================

# Rate Limit 1: Login Endpoint
resource "cloudflare_rate_limit" "login" {
  zone_id   = var.zone_id
  threshold = var.rate_limit_login_threshold
  period    = 60
  
  match {
    request {
      url_pattern = "${var.domain}/login*"
    }
  }
  
  action {
    mode    = "ban"
    timeout = 600  # 10 minutes
  }
  
  description = "Rate limit login attempts"
}

# Rate Limit 2: API Endpoints
resource "cloudflare_rate_limit" "api" {
  zone_id   = var.zone_id
  threshold = var.rate_limit_api_threshold
  period    = 60
  
  match {
    request {
      url_pattern = "${var.domain}/api/*"
    }
  }
  
  action {
    mode    = "simulate"  # Start with simulate, change to "ban" after testing
    timeout = 300  # 5 minutes
  }
  
  description = "Rate limit API requests"
}

# Rate Limit 3: Password Reset
resource "cloudflare_rate_limit" "password_reset" {
  zone_id   = var.zone_id
  threshold = 5
  period    = 3600  # 1 hour
  
  match {
    request {
      url_pattern = "${var.domain}/reset-password*"
    }
  }
  
  action {
    mode    = "ban"
    timeout = 3600  # 1 hour
  }
  
  description = "Rate limit password reset requests"
}

# ============================================
# WAF MANAGED RULESETS
# ============================================

# Enable OWASP ModSecurity Core Rule Set
resource "cloudflare_ruleset" "zone_level_managed_waf" {
  zone_id     = var.zone_id
  name        = "Managed WAF Ruleset"
  description = "Zone-level WAF Managed Ruleset"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  # OWASP ModSecurity Core Rule Set
  rules {
    action = "execute"
    action_parameters {
      id = "efb7b8c949ac4650a09736fc376e9aee"  # OWASP ruleset ID
    }
    expression  = "true"
    description = "Execute OWASP ruleset"
    enabled     = true
  }

  # Cloudflare Managed Ruleset
  rules {
    action = "execute"
    action_parameters {
      id = "4814384a9e5d4991b9815dcfc25d2f1f"  # Cloudflare Managed ruleset ID
    }
    expression  = "true"
    description = "Execute Cloudflare Managed ruleset"
    enabled     = true
  }
}

# ============================================
# PAGE RULES
# ============================================

# Page Rule 1: Force HTTPS
resource "cloudflare_page_rule" "force_https" {
  zone_id  = var.zone_id
  target   = "http://${var.domain}/*"
  priority = 1

  actions {
    always_use_https = true
  }
}

# Page Rule 2: Security Headers
resource "cloudflare_page_rule" "security_headers" {
  zone_id  = var.zone_id
  target   = "${var.domain}/*"
  priority = 2

  actions {
    security_level = var.security_level
    cache_level    = "standard"
  }
}

# ============================================
# CUSTOM HEADERS (Transform Rules)
# ============================================

resource "cloudflare_ruleset" "transform_response_headers" {
  zone_id     = var.zone_id
  name        = "Add Security Headers"
  description = "Add security headers to all responses"
  kind        = "zone"
  phase       = "http_response_headers_transform"

  rules {
    action = "rewrite"
    action_parameters {
      headers {
        name      = "Strict-Transport-Security"
        operation = "set"
        value     = "max-age=31536000; includeSubDomains; preload"
      }
      headers {
        name      = "X-Frame-Options"
        operation = "set"
        value     = "SAMEORIGIN"
      }
      headers {
        name      = "X-Content-Type-Options"
        operation = "set"
        value     = "nosniff"
      }
      headers {
        name      = "X-XSS-Protection"
        operation = "set"
        value     = "1; mode=block"
      }
      headers {
        name      = "Referrer-Policy"
        operation = "set"
        value     = "strict-origin-when-cross-origin"
      }
      headers {
        name      = "Permissions-Policy"
        operation = "set"
        value     = "geolocation=(), microphone=(), camera=()"
      }
    }
    expression  = "true"
    description = "Add security headers"
    enabled     = true
  }
}

# ============================================
# BOT MANAGEMENT (Free Tier)
# ============================================

resource "cloudflare_bot_management" "main" {
  count   = var.enable_bot_fight_mode ? 1 : 0
  zone_id = var.zone_id
  
  enable_js              = true
  fight_mode             = true
  suppress_session_score = false
}

# ============================================
# NOTIFICATIONS
# ============================================

resource "cloudflare_notification_policy" "waf_alerts" {
  account_id  = data.cloudflare_zone.main.account_id
  name        = "WAF Alert - High Block Rate"
  description = "Alert when WAF blocks more than 100 requests in 5 minutes"
  enabled     = true
  alert_type  = "firewall_events_alert"

  email_integration {
    id = "admin@yourapp.com"
  }

  filters {
    zones = [var.zone_id]
  }
}

# ============================================
# OUTPUTS
# ============================================

output "zone_id" {
  description = "Cloudflare Zone ID"
  value       = var.zone_id
}

output "zone_name" {
  description = "Cloudflare Zone name"
  value       = data.cloudflare_zone.main.name
}

output "nameservers" {
  description = "Cloudflare nameservers"
  value       = data.cloudflare_zone.main.name_servers
}

output "cloudflare_dashboard_url" {
  description = "Cloudflare Dashboard URL"
  value       = "https://dash.cloudflare.com/${data.cloudflare_zone.main.account_id}/${var.zone_id}/security/waf"
}

output "firewall_rules" {
  description = "Created firewall rules"
  value = {
    sql_injection   = cloudflare_firewall_rule.block_sql_injection.id
    xss             = cloudflare_firewall_rule.block_xss.id
    path_traversal  = cloudflare_firewall_rule.block_path_traversal.id
    bad_user_agents = cloudflare_firewall_rule.block_bad_user_agents.id
    suspicious      = cloudflare_firewall_rule.challenge_suspicious.id
  }
}

output "rate_limits" {
  description = "Created rate limit rules"
  value = {
    login          = cloudflare_rate_limit.login.id
    api            = cloudflare_rate_limit.api.id
    password_reset = cloudflare_rate_limit.password_reset.id
  }
}
