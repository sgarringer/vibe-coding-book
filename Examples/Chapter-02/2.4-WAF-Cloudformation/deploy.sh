#!/bin/bash
# ============================================
# AWS WAF CLOUDFORMATION DEPLOYMENT SCRIPT
# ============================================
# Usage: ./deploy.sh <template-file> <parameters-file> <stack-name>
# Example: ./deploy.sh waf-alb.yaml parameters.json yourapp-waf
# ============================================

set -e

# ============================================
# COLORS
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ============================================
# FUNCTIONS
# ============================================
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# ============================================
# VALIDATE ARGUMENTS
# ============================================
if [ $# -ne 3 ]; then
    print_error "Usage: $0 <template-file> <parameters-file> <stack-name>"
    exit 1
fi

TEMPLATE_FILE=$1
PARAMETERS_FILE=$2
STACK_NAME=$3

# Check if files exist
if [ ! -f "$TEMPLATE_FILE" ]; then
    print_error "Template file not found: $TEMPLATE_FILE"
    exit 1
fi

if [ ! -f "$PARAMETERS_FILE" ]; then
    print_error "Parameters file not found: $PARAMETERS_FILE"
    exit 1
fi

# ============================================
# VALIDATE TEMPLATE
# ============================================
print_info "Validating CloudFormation template..."

if aws cloudformation validate-template \
    --template-body file://"$TEMPLATE_FILE" > /dev/null 2>&1; then
    print_success "Template is valid"
else
    print_error "Template validation failed"
    exit 1
fi

# ============================================
# CHECK IF STACK EXISTS
# ============================================
print_info "Checking if stack exists..."

if aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" > /dev/null 2>&1; then
    
    STACK_EXISTS=true
    print_info "Stack exists. Will update."
else
    STACK_EXISTS=false
    print_info "Stack does not exist. Will create."
fi

# ============================================
# DEPLOY STACK
# ============================================

if [ "$STACK_EXISTS" = true ]; then
    # ============================================
    # UPDATE STACK
    # ============================================
    print_info "Creating change set..."
    
    CHANGE_SET_NAME="update-$(date +%Y%m%d-%H%M%S)"
    
    aws cloudformation create-change-set \
        --stack-name "$STACK_NAME" \
        --change-set-name "$CHANGE_SET_NAME" \
        --template-body file://"$TEMPLATE_FILE" \
        --parameters file://"$PARAMETERS_FILE" \
        --capabilities CAPABILITY_IAM
    
    print_success "Change set created: $CHANGE_SET_NAME"
    
    # Wait for change set creation
    print_info "Waiting for change set to be created..."
    aws cloudformation wait change-set-create-complete \
        --stack-name "$STACK_NAME" \
        --change-set-name "$CHANGE_SET_NAME"
    
    # Describe changes
    print_info "Changes to be applied:"
    aws cloudformation describe-change-set \
        --stack-name "$STACK_NAME" \
        --change-set-name "$CHANGE_SET_NAME" \
        --query 'Changes[].{Action:ResourceChange.Action,Resource:ResourceChange.LogicalResourceId,Type:ResourceChange.ResourceType}' \
        --output table
    
    # Confirm execution
    read -p "Execute change set? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        print_info "Aborting deployment"
        aws cloudformation delete-change-set \
            --stack-name "$STACK_NAME" \
            --change-set-name "$CHANGE_SET_NAME"
        exit 0
    fi
    
    # Execute change set
    print_info "Executing change set..."
    aws cloudformation execute-change-set \
        --stack-name "$STACK_NAME" \
        --change-set-name "$CHANGE_SET_NAME"
    
    # Wait for update
    print_info "Waiting for stack update to complete..."
    aws cloudformation wait stack-update-complete \
        --stack-name "$STACK_NAME"
    
    print_success "Stack updated successfully"
    
else
    # ============================================
    # CREATE STACK
    # ============================================
    print_info "Creating stack..."
    
    aws cloudformation create-stack \
        --stack-name "$STACK_NAME" \
        --template-body file://"$TEMPLATE_FILE" \
        --parameters file://"$PARAMETERS_FILE" \
        --capabilities CAPABILITY_IAM \
        --on-failure ROLLBACK
    
    print_success "Stack creation initiated"
    
    # Wait for creation
    print_info "Waiting for stack creation to complete..."
    aws cloudformation wait stack-create-complete \
        --stack-name "$STACK_NAME"
    
    print_success "Stack created successfully"
fi

# ============================================
# DISPLAY OUTPUTS
# ============================================
print_info "Stack outputs:"
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --query 'Stacks[0].Outputs' \
    --output table

# ============================================
# SUMMARY
# ============================================
echo ""
echo "============================================"
echo "DEPLOYMENT COMPLETE"
echo "============================================"
echo "Stack Name: $STACK_NAME"
echo "Region: $(aws configure get region)"
echo ""
echo "Next steps:"
echo "1. Test WAF rules: ./test-waf.sh https://yourapp.com"
echo "2. Monitor CloudWatch Logs: aws logs tail /aws/waf/$STACK_NAME --follow"
echo "3. View metrics in AWS Console"
echo "============================================"
