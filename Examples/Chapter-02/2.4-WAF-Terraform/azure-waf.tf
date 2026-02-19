# ============================================
# AZURE WAF TERRAFORM CONFIGURATION
# ============================================
# Referenced in: Vibe-Coded App Security Framework
# Chapter 2.4.2: WAF Deployment
#
# This configuration creates:
# - Azure Application Gateway with WAF
# - OWASP 3.2 Managed Rule Set
# - Custom rate limiting rules
# - Bot protection
# ============================================

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# ============================================
# VARIABLES
# ============================================

variable "resource_group_name" {
  description = "Azure Resource Group name"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "yourapp"
}

variable "vnet_address_space" {
  description = "Virtual Network address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "subnet_address_prefix" {
  description = "Application Gateway subnet address prefix"
  type        = string
  default     = "10.0.1.0/24"
}

variable "backend_address_pool" {
  description = "Backend server IP addresses or FQDNs"
  type        = list(string)
}

variable "waf_mode" {
  description = "WAF mode: Detection or Prevention"
  type        = string
  default     = "Prevention"
  
  validation {
    condition     = contains(["Detection", "Prevention"], var.waf_mode)
    error_message = "WAF mode must be either 'Detection' or 'Prevention'."
  }
}

variable "waf_rule_set_version" {
  description = "OWASP rule set version"
  type        = string
  default     = "3.2"
}

variable "enable_bot_protection" {
  description = "Enable bot protection"
  type        = bool
  default     = true
}

# ============================================
# RESOURCE GROUP
# ============================================

data "azurerm_resource_group" "main" {
  name = var.resource_group_name
}

# ============================================
# VIRTUAL NETWORK
# ============================================

resource "azurerm_virtual_network" "main" {
  name                = "${var.app_name}-vnet"
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location
  address_space       = var.vnet_address_space

  tags = {
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

# ============================================
# SUBNET FOR APPLICATION GATEWAY
# ============================================

resource "azurerm_subnet" "appgw" {
  name                 = "${var.app_name}-appgw-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.subnet_address_prefix]
}

# ============================================
# PUBLIC IP FOR APPLICATION GATEWAY
# ============================================

resource "azurerm_public_ip" "appgw" {
  name                = "${var.app_name}-appgw-pip"
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

# ============================================
# APPLICATION GATEWAY WITH WAF
# ============================================

resource "azurerm_application_gateway" "main" {
  name                = "${var.app_name}-appgw"
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location

  # ============================================
  # SKU (WAF_v2 required for WAF)
  # ============================================
  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }

  # ============================================
  # GATEWAY IP CONFIGURATION
  # ============================================
  gateway_ip_configuration {
    name      = "${var.app_name}-gateway-ip-config"
    subnet_id = azurerm_subnet.appgw.id
  }

  # ============================================
  # FRONTEND PORT
  # ============================================
  frontend_port {
    name = "${var.app_name}-frontend-port-80"
    port = 80
  }

  frontend_port {
    name = "${var.app_name}-frontend-port-443"
    port = 443
  }

  # ============================================
  # FRONTEND IP CONFIGURATION
  # ============================================
  frontend_ip_configuration {
    name                 = "${var.app_name}-frontend-ip"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }

  # ============================================
  # BACKEND ADDRESS POOL
  # ============================================
  backend_address_pool {
    name  = "${var.app_name}-backend-pool"
    fqdns = var.backend_address_pool
  }

  # ============================================
  # BACKEND HTTP SETTINGS
  # ============================================
  backend_http_settings {
    name                  = "${var.app_name}-backend-http-settings"
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 60
  }

  # ============================================
  # HTTP LISTENER
  # ============================================
  http_listener {
    name                           = "${var.app_name}-http-listener"
    frontend_ip_configuration_name = "${var.app_name}-frontend-ip"
    frontend_port_name             = "${var.app_name}-frontend-port-80"
    protocol                       = "Http"
  }

  # ============================================
  # REQUEST ROUTING RULE
  # ============================================
  request_routing_rule {
    name                       = "${var.app_name}-routing-rule"
    rule_type                  = "Basic"
    http_listener_name         = "${var.app_name}-http-listener"
    backend_address_pool_name  = "${var.app_name}-backend-pool"
    backend_http_settings_name = "${var.app_name}-backend-http-settings"
    priority                   = 100
  }

  # ============================================
  # WAF CONFIGURATION
  # ============================================
  waf_configuration {
    enabled          = true
    firewall_mode    = var.waf_mode
    rule_set_type    = "OWASP"
    rule_set_version = var.waf_rule_set_version

    # ============================================
    # DISABLED RULE GROUPS (for false positives)
    # ============================================
    # Uncomment and adjust as needed
    # disabled_rule_group {
    #   rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
    #   rules           = [920300, 920330]
    # }

    # ============================================
    # FILE UPLOAD LIMIT
    # ============================================
    file_upload_limit_mb = 100
    request_body_check   = true
    max_request_body_size_kb = 128
  }

  tags = {
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

# ============================================
# WAF POLICY (for advanced features)
# ============================================

resource "azurerm_web_application_firewall_policy" "main" {
  name                = "${var.app_name}-waf-policy"
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location

  # ============================================
  # POLICY SETTINGS
  # ============================================
  policy_settings {
    enabled                     = true
    mode                        = var.waf_mode
    request_body_check          = true
    file_upload_limit_in_mb     = 100
    max_request_body_size_in_kb = 128
  }

  # ============================================
  # MANAGED RULES
  # ============================================
  managed_rules {
    # OWASP Rule Set
    managed_rule_set {
      type    = "OWASP"
      version = var.waf_rule_set_version

      # Exclude specific rules if needed (false positives)
      # rule_group_override {
      #   rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
      #   
      #   rule {
      #     id      = "920300"
      #     enabled = false
      #     action  = "Log"
      #   }
      # }
    }

    # Bot Protection (if enabled)
    dynamic "managed_rule_set" {
      for_each = var.enable_bot_protection ? [1] : []
      
      content {
        type    = "Microsoft_BotManagerRuleSet"
        version = "0.1"
      }
    }
  }

  # ============================================
  # CUSTOM RULES
  # ============================================

  # Custom Rule 1: Rate Limiting for Login
  custom_rules {
    name      = "RateLimitLogin"
    priority  = 10
    rule_type = "RateLimitRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestUri"
      }

      operator           = "Contains"
      negation_condition = false
      match_values       = ["/login", "/signin", "/auth"]
    }

    rate_limit_duration_in_minutes = 5
    rate_limit_threshold           = 100
  }

  # Custom Rule 2: Rate Limiting for API
  custom_rules {
    name      = "RateLimitAPI"
    priority  = 20
    rule_type = "RateLimitRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestUri"
      }

      operator           = "BeginsWith"
      negation_condition = false
      match_values       = ["/api/"]
    }

    rate_limit_duration_in_minutes = 5
    rate_limit_threshold           = 2000
  }

  # Custom Rule 3: Block SQL Injection Patterns
  custom_rules {
    name      = "BlockSQLInjection"
    priority  = 30
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "QueryString"
      }

      operator           = "Contains"
      negation_condition = false
      match_values       = [
        "' OR '1'='1",
        "' OR 1=1",
        "UNION SELECT",
        "DROP TABLE",
        "'; DROP",
        "1' AND '1'='1"
      ]
      transforms = ["Lowercase", "UrlDecode"]
    }
  }

  # Custom Rule 4: Block XSS Patterns
  custom_rules {
    name      = "BlockXSS"
    priority  = 40
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "QueryString"
      }

      operator           = "Contains"
      negation_condition = false
      match_values       = [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        "<iframe"
      ]
      transforms = ["Lowercase", "HtmlEntityDecode"]
    }
  }

  # Custom Rule 5: Block Path Traversal
  custom_rules {
    name      = "BlockPathTraversal"
    priority  = 50
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestUri"
      }

      operator           = "Contains"
      negation_condition = false
      match_values       = [
        "../",
        "..\\",
        "/etc/passwd",
        "/etc/shadow",
        "c:\\windows"
      ]
      transforms = ["Lowercase", "UrlDecode"]
    }
  }

  # Custom Rule 6: Geo-Blocking (optional)
  # Uncomment to enable
  # custom_rules {
  #   name      = "GeoBlocking"
  #   priority  = 60
  #   rule_type = "MatchRule"
  #   action    = "Block"
  #
  #   match_conditions {
  #     match_variables {
  #       variable_name = "RemoteAddr"
  #     }
  #
  #     operator           = "GeoMatch"
  #     negation_condition = false
  #     match_values       = ["CN", "RU", "KP"]  # Country codes to block
  #   }
  # }

  tags = {
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

# ============================================
# ASSOCIATE WAF POLICY WITH APPLICATION GATEWAY
# ============================================

resource "azurerm_web_application_firewall_policy_association" "main" {
  web_application_firewall_policy_id = azurerm_web_application_firewall_policy.main.id
  application_gateway_id             = azurerm_application_gateway.main.id
}

# ============================================
# DIAGNOSTIC SETTINGS (Logging)
# ============================================

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.app_name}-log-analytics"
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

resource "azurerm_monitor_diagnostic_setting" "appgw" {
  name                       = "${var.app_name}-appgw-diagnostics"
  target_resource_id         = azurerm_application_gateway.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ApplicationGatewayAccessLog"
  }

  enabled_log {
    category = "ApplicationGatewayPerformanceLog"
  }

  enabled_log {
    category = "ApplicationGatewayFirewallLog"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# ============================================
# ALERTS
# ============================================

resource "azurerm_monitor_action_group" "main" {
  name                = "${var.app_name}-action-group"
  resource_group_name = data.azurerm_resource_group.main.name
  short_name          = "waf-alert"

  email_receiver {
    name          = "admin"
    email_address = "admin@yourapp.com"
  }

  tags = {
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

resource "azurerm_monitor_metric_alert" "blocked_requests" {
  name                = "${var.app_name}-waf-blocked-requests"
  resource_group_name = data.azurerm_resource_group.main.name
  scopes              = [azurerm_application_gateway.main.id]
  description         = "Alert when WAF blocks more than 100 requests"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.Network/applicationGateways"
    metric_name      = "BlockedCount"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 100
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }

  tags = {
    Environment = terraform.workspace
    ManagedBy   = "Terraform"
  }
}

# ============================================
# OUTPUTS
# ============================================

output "application_gateway_id" {
  description = "Application Gateway ID"
  value       = azurerm_application_gateway.main.id
}

output "application_gateway_public_ip" {
  description = "Application Gateway public IP address"
  value       = azurerm_public_ip.appgw.ip_address
}

output "waf_policy_id" {
  description = "WAF Policy ID"
  value       = azurerm_web_application_firewall_policy.main.id
}

output "log_analytics_workspace_id" {
  description = "Log Analytics Workspace ID"
  value       = azurerm_log_analytics_workspace.main.id
}

output "azure_portal_url" {
  description = "Azure Portal URL for Application Gateway"
  value       = "https://portal.azure.com/#@/resource${azurerm_application_gateway.main.id}/overview"
}
