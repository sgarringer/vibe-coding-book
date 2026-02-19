# AWS WAF CloudFormation Examples

CloudFormation templates for deploying AWS WAF with Application Load Balancer or CloudFront.

Referenced in Chapter 2.4.2 and Chapter 4.2 of the Vibe-Coded App Security Framework.

## Why Use CloudFormation?

- **Native AWS Integration** - No third-party tools required
- **Version Control** - Track infrastructure changes in Git
- **Rollback Support** - Automatic rollback on failure
- **Stack Management** - Deploy/update/delete as a unit
- **Change Sets** - Preview changes before applying

## Prerequisites

### AWS CLI

```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
```
### Validate Templates
```bash
# Validate CloudFormation template
aws cloudformation validate-template \
  --template-body file://waf-alb.yaml
```
## Files in This Directory
- ```waf-alb.yaml``` - WAF with Application Load Balancer
- ```waf-cloudfront.yaml``` - WAF with CloudFront distribution
- ```waf-rules-only.yaml``` - WAF rules only (for existing infrastructure)
- ```parameters.json.example``` - Example parameters file
- ```deploy.sh``` - Deployment script
- ```test-waf.sh``` - WAF testing script

## Quick Start
### 1. Configure Parameters
```bash
# Copy example parameters
cp parameters.json.example parameters.json

# Edit with your values
nano parameters.json
```
### 2. Deploy Stack
```bash
# Deploy WAF with ALB
./deploy.sh waf-alb.yaml parameters.json yourapp-waf

# Or manually:
aws cloudformation create-stack \
  --stack-name yourapp-waf \
  --template-body file://waf-alb.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_IAM
```

### 3. Monitor Deployment
```bash
# Watch stack creation
aws cloudformation describe-stacks \
  --stack-name yourapp-waf \
  --query 'Stacks[0].StackStatus'

# View events
aws cloudformation describe-stack-events \
  --stack-name yourapp-waf
```
### 4. Get Outputs
```bash
# Get stack outputs
aws cloudformation describe-stacks \
  --stack-name yourapp-waf \
  --query 'Stacks[0].Outputs'
```

### 5. Test WAF
```bash
# Run test suite
./test-waf.sh https://yourapp.com
```

## Stack Components
### WAF with ALB Stack

- AWS WAFv2 Web ACL
- AWS Managed Rule Groups (Core, SQL Injection, Known Bad Inputs)
- Custom rate limiting rules
- CloudWatch Log Group
- CloudWatch Alarms
- Association with ALB

### WAF with CloudFront Stack
- AWS WAFv2 Web ACL (CLOUDFRONT scope)
- AWS Managed Rule Groups
- Custom rules for CloudFront
- CloudWatch metrics
- Association with CloudFront distribution

### Update Stack
```bash
# Create change set
aws cloudformation create-change-set \
  --stack-name yourapp-waf \
  --change-set-name update-$(date +%Y%m%d-%H%M%S) \
  --template-body file://waf-alb.yaml \
  --parameters file://parameters.json

# Review changes
aws cloudformation describe-change-set \
  --stack-name yourapp-waf \
  --change-set-name update-20240101-120000

# Execute change set
aws cloudformation execute-change-set \
  --stack-name yourapp-waf \
  --change-set-name update-20240101-120000
```
### Delete Stack
```bash
# Delete stack (removes all resources)
aws cloudformation delete-stack \
  --stack-name yourapp-waf

# Wait for deletion
aws cloudformation wait stack-delete-complete \
  --stack-name yourapp-waf
Warning: This will delete all WAF rules and configurations.
```

## Cost Estimates
### AWS WAF
- Web ACL: $5/month
- Rules: $1/month per rule (5 rules = $5/month)
- Requests: $0.60 per million requests
- Typical cost: $20-50/month for small-medium traffic

### CloudWatch Logs
- Ingestion: $0.50 per GB
- Storage: $0.03 per GB/month
- Typical cost: $5-20/month

## Monitoring
### View WAF Metrics
```bash
# Blocked requests (last hour)
aws cloudwatch get-metric-statistics \
  --namespace AWS/WAFV2 \
  --metric-name BlockedRequests \
  --dimensions Name=WebACL,Value=yourapp-waf Name=Region,Value=us-east-1 Name=Rule,Value=ALL \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```
### View WAF Logs
```bash
# Query CloudWatch Logs
aws logs tail /aws/waf/yourapp --follow
```

### CloudWatch Dashboard
Access in AWS Console:

- CloudWatch → Dashboards → yourapp-waf-dashboard

## Troubleshooting
### Stack Creation Failed
```bash
# View failure reason
aws cloudformation describe-stack-events \
  --stack-name yourapp-waf \
  --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`]'

# Common issues:
# - Invalid ALB ARN
# - Insufficient permissions
# - Resource limits exceeded
```
### False Positives
If legitimate requests are blocked:

1. Check CloudWatch Logs for rule ID
2. Update template to exclude rule
3. Create change set and apply
```bash
# In template, add to managed rule group:
ExcludedRules:
  - Name: SizeRestrictions_BODY
```
### High Costs
Monitor request volume:
```bash

# Total requests (last 24 hours)
aws cloudwatch get-metric-statistics \
  --namespace AWS/WAFV2 \
  --metric-name AllowedRequests \
  --dimensions Name=WebACL,Value=yourapp-waf \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 86400 \
  --statistics Sum
```
## Related
- Chapter 2.4.2: WAF Deployment
- Chapter 4.2: Cloud Provider Security
- Terraform examples: ../waf-terraform/