#!/usr/bin/env bash
# AWS CloudWatch Logging Setup
# Chapter 2.10.5
#
# Prerequisites:
#   - AWS CLI installed and configured (aws configure)
#   - IAM permissions: logs:CreateLogGroup, logs:CreateLogStream,
#                      logs:PutLogEvents, logs:PutRetentionPolicy
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# Environment variables (override defaults by exporting before running):
#   APP_NAME        - Your application name       (default: my-app)
#   AWS_REGION      - AWS region                  (default: us-east-1)
#   ENV             - Deployment environment       (default: production)

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

APP_NAME="${APP_NAME:-my-app}"
AWS_REGION="${AWS_REGION:-us-east-1}"
ENV="${ENV:-production}"

# Log group names — one per retention tier (Table 2.19)
LOG_GROUP_SECURITY="/app/${APP_NAME}/${ENV}/security"   # 1 year  — auth, authz, config changes
LOG_GROUP_APP="/app/${APP_NAME}/${ENV}/application"     # 30 days — errors, API calls
LOG_GROUP_AUDIT="/app/${APP_NAME}/${ENV}/audit"         # 1 year  — data access, privilege changes

# Retention periods in days (Table 2.19)
RETENTION_SECURITY=365
RETENTION_APP=30
RETENTION_AUDIT=365

# SNS topic for alerts (Section 2.10.6) — set this to your existing topic ARN
# or leave blank to create a new one
SNS_TOPIC_ARN="${SNS_TOPIC_ARN:-}"
ALERT_EMAIL="${ALERT_EMAIL:-security@example.com}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
die()     { echo "[ERROR] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."
}

# ─── Preflight Checks ─────────────────────────────────────────────────────────

require_cmd aws
require_cmd jq

info "Verifying AWS credentials..."
aws sts get-caller-identity --region "${AWS_REGION}" --output table \
  || die "AWS credentials not configured. Run: aws configure"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
info "Account ID : ${ACCOUNT_ID}"
info "Region     : ${AWS_REGION}"
info "App        : ${APP_NAME} (${ENV})"
echo ""

# ─── Create Log Groups ────────────────────────────────────────────────────────

create_log_group() {
  local group="$1"
  local retention="$2"
  local description="$3"

  info "Creating log group: ${group}"

  # Create the group (idempotent — no error if it already exists)
  aws logs create-log-group \
    --log-group-name "${group}" \
    --region "${AWS_REGION}" \
    --tags \
      "App=${APP_NAME}" \
      "Environment=${ENV}" \
      "ManagedBy=setup.sh" \
    2>/dev/null || true

  # Set retention policy
  aws logs put-retention-policy \
    --log-group-name "${group}" \
    --retention-in-days "${retention}" \
    --region "${AWS_REGION}"

  success "${group} — retention: ${retention} days (${description})"
}

info "=== Creating Log Groups ==="
create_log_group "${LOG_GROUP_SECURITY}" "${RETENTION_SECURITY}" "auth, authz, security events"
create_log_group "${LOG_GROUP_APP}"      "${RETENTION_APP}"      "errors, API calls"
create_log_group "${LOG_GROUP_AUDIT}"    "${RETENTION_AUDIT}"    "data access, privilege changes"
echo ""

# ─── Create IAM Policy for Log Shipping ───────────────────────────────────────
# Attach this policy to your application's IAM role so it can write logs.

POLICY_NAME="${APP_NAME}-${ENV}-log-writer"
POLICY_DOC=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateLogStreams",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:DescribeLogStreams"
      ],
      "Resource": [
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_SECURITY}:*",
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_APP}:*",
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_AUDIT}:*"
      ]
    },
    {
      "Sid": "PutLogEvents",
      "Effect": "Allow",
      "Action": "logs:PutLogEvents",
      "Resource": [
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_SECURITY}:log-stream:*",
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_APP}:log-stream:*",
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_AUDIT}:log-stream:*"
      ]
    }
  ]
}
EOF
)

info "=== Creating IAM Log Writer Policy ==="

# Check if policy already exists
EXISTING_POLICY_ARN=$(aws iam list-policies \
  --scope Local \
  --query "Policies[?PolicyName=='${POLICY_NAME}'].Arn" \
  --output text 2>/dev/null || true)

if [ -n "${EXISTING_POLICY_ARN}" ]; then
  warn "Policy ${POLICY_NAME} already exists: ${EXISTING_POLICY_ARN}"
  warn "Skipping creation. Update manually if needed."
  POLICY_ARN="${EXISTING_POLICY_ARN}"
else
  POLICY_ARN=$(aws iam create-policy \
    --policy-name "${POLICY_NAME}" \
    --policy-document "${POLICY_DOC}" \
    --description "Allows ${APP_NAME} to write logs to CloudWatch" \
    --query "Policy.Arn" \
    --output text)
  success "Created IAM policy: ${POLICY_ARN}"
fi
echo ""

# ─── SNS Topic for Alerts ─────────────────────────────────────────────────────
# Used by the CloudWatch alarms in alerting/cloudwatch-alarms.sh (Section 2.10.6)

info "=== Setting Up SNS Alert Topic ==="

if [ -z "${SNS_TOPIC_ARN}" ]; then
  TOPIC_NAME="${APP_NAME}-${ENV}-security-alerts"
  SNS_TOPIC_ARN=$(aws sns create-topic \
    --name "${TOPIC_NAME}" \
    --region "${AWS_REGION}" \
    --query "TopicArn" \
    --output text)
  success "Created SNS topic: ${SNS_TOPIC_ARN}"

  # Subscribe the alert email address
  aws sns subscribe \
    --topic-arn "${SNS_TOPIC_ARN}" \
    --protocol email \
    --notification-endpoint "${ALERT_EMAIL}" \
    --region "${AWS_REGION}" > /dev/null
  success "Subscribed ${ALERT_EMAIL} — check inbox to confirm subscription"
else
  success "Using existing SNS topic: ${SNS_TOPIC_ARN}"
fi
echo ""

# ─── Metric Filters ───────────────────────────────────────────────────────────
# These turn log events into CloudWatch metrics so alarms can trigger on them.
# See Section 2.10.6 for the alarm definitions.

info "=== Creating Metric Filters ==="

# Filter 1: Failed login attempts → used by brute force alarm (Alert 1)
aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP_SECURITY}" \
  --filter-name "FailedLogins" \
  --filter-pattern '{ $.event = "auth.login.failure" }' \
  --metric-transformations \
    "metricName=FailedLoginCount,metricNamespace=${APP_NAME}/Security,metricValue=1,defaultValue=0" \
  --region "${AWS_REGION}"
success "Metric filter: FailedLoginCount"

# Filter 2: Authorization failures → used by authz alarm (Alert 2)
aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP_SECURITY}" \
  --filter-name "AuthorizationFailures" \
  --filter-pattern '{ $.event = "authz.failure" }' \
  --metric-transformations \
    "metricName=AuthorizationFailureCount,metricNamespace=${APP_NAME}/Security,metricValue=1,defaultValue=0" \
  --region "${AWS_REGION}"
success "Metric filter: AuthorizationFailureCount"

# Filter 3: Generic security events → used by security event alarm (Alert 3)
aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP_SECURITY}" \
  --filter-name "SecurityEvents" \
  --filter-pattern '{ $.event = "security.event" }' \
  --metric-transformations \
    "metricName=SecurityEventCount,metricNamespace=${APP_NAME}/Security,metricValue=1,defaultValue=0" \
  --region "${AWS_REGION}"
success "Metric filter: SecurityEventCount"

# Filter 4: Privilege changes — always worth alerting on
aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP_AUDIT}" \
  --filter-name "PrivilegeChanges" \
  --filter-pattern '{ $.event = "authz.privilege.change" }' \
  --metric-transformations \
    "metricName=PrivilegeChangeCount,metricNamespace=${APP_NAME}/Security,metricValue=1,defaultValue=0" \
  --region "${AWS_REGION}"
success "Metric filter: PrivilegeChangeCount"
echo ""

# ─── CloudWatch Alarms ────────────────────────────────────────────────────────
# Implements the three alerts from Section 2.10.6.

info "=== Creating CloudWatch Alarms ==="

# Alert 1: Brute force detection
# Trigger: 5+ failed logins from any source within 15 minutes
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-BruteForceDetection" \
  --alarm-description "Alert 1 (Section 2.10.6): 5+ failed logins in 15 minutes" \
  --metric-name "FailedLoginCount" \
  --namespace "${APP_NAME}/Security" \
  --statistic "Sum" \
  --period 900 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}"
success "Alarm: BruteForceDetection (≥5 failures / 15 min)"

# Alert 2: Authorization failure spike
# Trigger: 10+ authorization failures from any user within 5 minutes
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-AuthorizationFailureSpike" \
  --alarm-description "Alert 2 (Section 2.10.6): 10+ authorization failures in 5 minutes" \
  --metric-name "AuthorizationFailureCount" \
  --namespace "${APP_NAME}/Security" \
  --statistic "Sum" \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 10 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}"
success "Alarm: AuthorizationFailureSpike (≥10 failures / 5 min)"

# Alert 3: Any security event
# Trigger: Any event logged as security.event
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-SecurityEvent" \
  --alarm-description "Alert 3 (Section 2.10.6): Any security.event logged" \
  --metric-name "SecurityEventCount" \
  --namespace "${APP_NAME}/Security" \
  --statistic "Sum" \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}"
success "Alarm: SecurityEvent (any security.event within 1 min)"

# Alert 4: Privilege change
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-PrivilegeChange" \
  --alarm-description "Any privilege change logged" \
  --metric-name "PrivilegeChangeCount" \
  --namespace "${APP_NAME}/Security" \
  --statistic "Sum" \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}"
success "Alarm: PrivilegeChange (any privilege change within 1 min)"
echo ""

# ─── Log Access Control ───────────────────────────────────────────────────────
# Implements Section 2.10.7 — restrict who can read security logs.

info "=== Creating Log Reader Policies ==="

# Security team policy — full access to all log groups
SECURITY_READER_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityTeamFullLogAccess",
      "Effect": "Allow",
      "Action": [
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:StartQuery",
        "logs:GetQueryResults"
      ],
      "Resource": [
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_SECURITY}:*",
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_APP}:*",
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_AUDIT}:*"
      ]
    }
  ]
}
EOF
)

# Developer policy — application errors only, no security or audit logs
DEV_READER_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeveloperAppLogAccess",
      "Effect": "Allow",
      "Action": [
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "logs:DescribeLogStreams",
        "logs:StartQuery",
        "logs:GetQueryResults"
      ],
      "Resource": [
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_APP}:*"
      ]
    },
    {
      "Sid": "DenySecurityAndAuditLogs",
      "Effect": "Deny",
      "Action": "logs:*",
      "Resource": [
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_SECURITY}:*",
        "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_AUDIT}:*"
      ]
    }
  ]
}
EOF
)

# Create security team reader policy
aws iam create-policy \
  --policy-name "${APP_NAME}-${ENV}-security-log-reader" \
  --policy-document "${SECURITY_READER_POLICY}" \
  --description "Security team: full read access to all log groups" \
  --output text > /dev/null 2>/dev/null || \
  warn "Policy ${APP_NAME}-${ENV}-security-log-reader already exists, skipping"
success "IAM policy: ${APP_NAME}-${ENV}-security-log-reader"

# Create developer reader policy
aws iam create-policy \
  --policy-name "${APP_NAME}-${ENV}-developer-log-reader" \
  --policy-document "${DEV_READER_POLICY}" \
  --description "Developers: application errors only, no security/audit logs" \
  --output text > /dev/null 2>/dev/null || \
  warn "Policy ${APP_NAME}-${ENV}-developer-log-reader already exists, skipping"
success "IAM policy: ${APP_NAME}-${ENV}-developer-log-reader"
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "============================================================"
echo " Setup Complete"
echo "============================================================"
echo ""
echo " Log Groups:"
echo "   Security : ${LOG_GROUP_SECURITY} (${RETENTION_SECURITY} days)"
echo "   App      : ${LOG_GROUP_APP} (${RETENTION_APP} days)"
echo "   Audit    : ${LOG_GROUP_AUDIT} (${RETENTION_AUDIT} days)"
echo ""
echo " IAM Policy (attach to your app's role):"
echo "   ${POLICY_ARN}"
echo ""
echo " SNS Alert Topic:"
echo "   ${SNS_TOPIC_ARN}"
echo "   → Confirm subscription in ${ALERT_EMAIL}'s inbox"
echo ""
echo " Alarms:"
echo "   BruteForceDetection       — ≥5 failed logins / 15 min"
echo "   AuthorizationFailureSpike — ≥10 authz failures / 5 min"
echo "   SecurityEvent             — any security.event"
echo "   PrivilegeChange           — any privilege change"
echo ""
echo " Next Steps:"
echo "   1. Confirm SNS email subscription"
echo "   2. Attach ${POLICY_ARN} to your application's IAM role"
echo "   3. Configure your app to ship logs — see nodejs-cloudwatch.js"
echo "   4. Verify logs appear: AWS Console → CloudWatch → Log Groups"
echo "   5. Set up log access for your team — see IAM policies above"
echo "============================================================"
