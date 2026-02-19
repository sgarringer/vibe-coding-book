# WAF Terraform Examples

Infrastructure as Code examples for deploying Web Application Firewalls (WAF) on AWS, Azure, and Cloudflare.

Referenced in Chapter 2.4.2 and Chapter 4.2 of the Vibe-Coded App Security Framework.

## Why Use Infrastructure as Code for WAF?

- **Version Control** - Track changes to WAF rules over time
- **Reproducibility** - Deploy identical configurations across environments
- **Automation** - Integrate with CI/CD pipelines
- **Documentation** - Code serves as documentation
- **Disaster Recovery** - Quickly rebuild infrastructure

## Prerequisites

### Terraform

```bash
# Install Terraform
# macOS
brew install terraform

# Linux
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# Verify installation
terraform --version
```

## Cloud Provider CLI
### AWS
```
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
```

### Azure
```
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login
az login
```

### Cloudflare
```
# Get API token from Cloudflare dashboard
# Settings → API Tokens → Create Token
```

## Files in This Directory
- ```aws-waf.tf``` - AWS WAF with Application Load Balancer
- ```azure-waf.tf``` - Azure WAF with Application Gateway
- ```cloudflare-waf.tf``` - Cloudflare WAF rules
- ```variables.tf``` - Common variables
- ```outputs.tf``` - Output values
- ```terraform.tfvars.example``` - Example configuration

## Quick Start

### 1. Clone and Configure

```
# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit with your values
nano terraform.tfvars
```

### 2. Initialize Terraform

```
terraform init
```

### 3. Plan Deployment

```
# Preview changes
terraform plan
```

### 4. Deploy

```
# Apply configuration
terraform apply

# Confirm with 'yes'
```

### 5. Verify

```
# Show outputs
terraform output

# Test WAF rules
curl -X POST https://yourapp.com/login \
  -d "username=admin' OR '1'='1" \
  -d "password=test"
# Should be blocked by WAF
```
## WAF Rule Sets
### AWS Managed Rules
- Core Rule Set - OWASP Top 10 protection
- Known Bad Inputs - Known malicious patterns
- SQL Injection - SQL injection protection
- Linux Operating System - Linux-specific attacks
- POSIX Operating System - POSIX-specific attacks
- Windows Operating System - Windows-specific attacks
- PHP Application - PHP-specific attacks
- WordPress Application - WordPress-specific attacks

### Azure Managed Rules
- OWASP 3.2 - OWASP Top 10 protection
- Bot Protection - Bot mitigation
- Microsoft Threat Intelligence - Microsoft's threat data

### Cloudflare Managed Rules
- OWASP ModSecurity Core Rule Set
- Cloudflare Managed Ruleset
- Cloudflare Rate Limiting

## Custom Rules

All examples include custom rules for:

- Rate limiting on login endpoints
- Rate limiting on API endpoints
- Blocking common attack patterns
- Geo-blocking (optional)

## Cost Estimates
### AWS WAF
- Web ACL: $5/month
- Rules: $1/month per rule
- Requests: $0.60 per million requests
- Typical cost: $20-50/month

### Azure WAF
- Application Gateway WAF: $125/month (gateway) + $0.008/GB processed
- Front Door WAF: $35/month + $0.06 per million requests
- Typical cost: $150-300/month

### Cloudflare WAF
- Pro Plan: $20/month (includes WAF)
- Business Plan: $200/month (advanced WAF)
- Enterprise: Custom pricing

## Testing WAF Rules
### Test SQL Injection Protection

```
# Should be blocked
curl "https://yourapp.com/api/users?id=1' OR '1'='1"

# Should be blocked
curl -X POST https://yourapp.com/login \
  -d "username=admin' OR '1'='1" \
  -d "password=test"
```
### Test XSS Protection

```
# Should be blocked
curl "https://yourapp.com/search?q=<script>alert('xss')</script>"

# Should be blocked
curl -X POST https://yourapp.com/comment \
  -d "text=<img src=x onerror=alert('xss')>"
```

### Test Rate Limiting

```
# Should be blocked after 10 requests in 5 minutes
for i in {1..15}; do
  curl -X POST https://yourapp.com/login \
    -d "username=test" \
    -d "password=wrong"
  sleep 1
done
```

### Test Path Traversal Protection

```
# Should be blocked
curl "https://yourapp.com/files?path=../../etc/passwd"
```

## Monitoring
### AWS CloudWatch
```
# View WAF metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/WAFV2 \
  --metric-name BlockedRequests \
  --dimensions Name=WebACL,Value=yourapp-waf \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Sum
```
### Azure Monitor
```
# View WAF logs
az monitor metrics list \
  --resource /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Network/applicationGateways/{gateway-name} \
  --metric BlockedRequests
```
### Cloudflare Analytics
View in Cloudflare Dashboard:

- Security → WAF
- Analytics → Security

## Maintenance
### Update Managed Rules

```
# AWS: Managed rules auto-update
# No action needed

# Azure: Update rule set version
terraform apply -var="waf_rule_set_version=3.2"

# Cloudflare: Managed rules auto-update
# No action needed
```

### Add Custom Rules

1. Edit aws-waf.tf (or appropriate file)
2. Add rule to custom_rules block
3. Apply changes:
    ```
    terraform plan
    terraform apply
    ```
### Disable Rules (False Positives)
If a rule causes false positives:

1. Identify rule ID from logs
2. Add to exclusions in Terraform
3. Apply changes

### Cleanup
```
# Destroy all resources
terraform destroy

# Confirm with 'yes'
```
**Warning:** This will delete all WAF rules and configurations.

## Troubleshooting
### False Positives
**Problem:** Legitimate requests blocked by WAF

**Solution:**

1. Check WAF logs for rule ID
2. Add exclusion for specific rule
3. Or adjust rule sensitivity

### High Costs
**Problem:** WAF costs higher than expected

**Solution:**

1. Review request volume
2. Optimize rules (fewer rules = lower cost)
3. Use managed rules (more efficient)

### Rules Not Blocking
**Problem:** Malicious requests not blocked

**Solution:**

1. Verify WAF is associated with resource
2. Check rule priority (lower number = higher priority)
3. Test with known attack patterns
4. Review CloudWatch/Azure Monitor logs

## Related

- Chapter 2.4.2: WAF Deployment
- Chapter 4.2: Cloud Provider Security
- CloudFormation examples: ../waf-cloudformation/