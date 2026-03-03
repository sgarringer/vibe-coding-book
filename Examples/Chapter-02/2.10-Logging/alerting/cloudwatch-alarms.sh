#!/usr/bin/env bash
# CloudWatch Alarms — Three Required Security Alerts
# Chapter 2.10.6
#
# Creates the metric filters and alarms for all three alerts
# defined in Section 2.10.6.
#
# Prerequisites:
#   - AWS CLI installed and configured
#   - Log groups created by ../centralized/aws-cloudwatch/setup.sh
#   - SNS topic created by setup.sh (or provide SNS_TOPIC_ARN)
#
# Usage:
#   export SNS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789:security-alerts
#   chmod +x cloudwatch-alarms.sh
#   ./cloudwatch-alarms.sh

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

APP_NAME="${APP_NAME:-my-app}"
ENV="${ENV:-production}"
AWS_REGION="${AWS_REGION:-us-east-1}"
SNS_TOPIC_ARN="${SNS_TOPIC_ARN:-}"
ALERT_EMAIL="${ALERT_EMAIL:-security@example.com}"

# Log group names — must match what setup.sh created
LOG_GROUP_SECURITY="/app/${APP_NAME}/${ENV}/security"
LOG_GROUP_AUDIT="/app/${APP_NAME}/${ENV}/audit"

# CloudWatch metric namespace
NAMESPACE="${APP_NAME}/Security"

# ─── Helpers ──────────────────────────────────────────────────────────────────

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
die()     { echo "[ERROR] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."
}

# ─── Preflight ────────────────────────────────────────────────────────────────

require_cmd aws

aws sts get-caller-identity --region "${AWS_REGION}" --output table \
  || die "AWS credentials not configured. Run: aws configure"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

info "Account : ${ACCOUNT_ID}"
info "Region  : ${AWS_REGION}"
info "App     : ${APP_NAME} (${ENV})"
echo ""

# ─── SNS Topic ────────────────────────────────────────────────────────────────

if [ -z "${SNS_TOPIC_ARN}" ]; then
  info "=== Creating SNS Alert Topic ==="
  TOPIC_NAME="${APP_NAME}-${ENV}-security-alerts"

  SNS_TOPIC_ARN=$(aws sns create-topic \
    --name "${TOPIC_NAME}" \
    --region "${AWS_REGION}" \
    --query "TopicArn" \
    --output text)
  success "Created SNS topic: ${SNS_TOPIC_ARN}"

  aws sns subscribe \
    --topic-arn "${SNS_TOPIC_ARN}" \
    --protocol email \
    --notification-endpoint "${ALERT_EMAIL}" \
    --region "${AWS_REGION}" > /dev/null
  success "Subscribed ${ALERT_EMAIL} — check inbox to confirm"
  echo ""
else
  info "Using existing SNS topic: ${SNS_TOPIC_ARN}"
  echo ""
fi

# ─── Metric Filters ───────────────────────────────────────────────────────────
# Each filter extracts a specific event type from the log stream
# and increments a CloudWatch metric counter.
# The alarms below trigger when those counters cross thresholds.

info "=== Creating Metric Filters ==="

# ── Alert 1: Failed Logins ────────────────────────────────────────────────────
# Matches: { "event": "auth.login.failure", ... }
aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP_SECURITY}" \
  --filter-name "${APP_NAME}-FailedLogins" \
  --filter-pattern '{ $.event = "auth.login.failure" }' \
  --metric-transformations \
    "metricName=FailedLoginCount,\
metricNamespace=${NAMESPACE},\
metricValue=1,\
defaultValue=0,\
dimensions={IP=$.ip}" \
  --region "${AWS_REGION}"
success "Metric filter: FailedLoginCount (by IP)"

# ── Alert 2: Authorization Failures ──────────────────────────────────────────
# Matches: { "event": "authz.failure", ... }
aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP_SECURITY}" \
  --filter-name "${APP_NAME}-AuthorizationFailures" \
  --filter-pattern '{ $.event = "authz.failure" }' \
  --metric-transformations \
    "metricName=AuthorizationFailureCount,\
metricNamespace=${NAMESPACE},\
metricValue=1,\
defaultValue=0,\
dimensions={UserId=$.userId}" \
  --region "${AWS_REGION}"
success "Metric filter: AuthorizationFailureCount (by userId)"

# ── Alert 3: Security Events ──────────────────────────────────────────────────
# Matches: { "event": "security.event", ... }
aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP_SECURITY}" \
  --filter-name "${APP_NAME}-SecurityEvents" \
  --filter-pattern '{ $.event = "security.event" }' \
  --metric-transformations \
    "metricName=SecurityEventCount,\
metricNamespace=${NAMESPACE},\
metricValue=1,\
defaultValue=0" \
  --region "${AWS_REGION}"
success "Metric filter: SecurityEventCount"

# ── Bonus: Privilege Changes ──────────────────────────────────────────────────
# Any privilege change is worth an immediate alert
aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP_AUDIT}" \
  --filter-name "${APP_NAME}-PrivilegeChanges" \
  --filter-pattern '{ $.event = "authz.privilege.change" }' \
  --metric-transformations \
    "metricName=PrivilegeChangeCount,\
metricNamespace=${NAMESPACE},\
metricValue=1,\
defaultValue=0" \
  --region "${AWS_REGION}"
success "Metric filter: PrivilegeChangeCount"

# ── Bonus: Log Deletion (Section 2.10.7) ─────────────────────────────────────
# Alert if anyone deletes or modifies log groups — sign of cover-up
aws logs put-metric-filter \
  --log-group-name "CloudTrail/DefaultLogGroup" \
  --filter-name "${APP_NAME}-LogDeletion" \
  --filter-pattern '{ $.eventName = "DeleteLogGroup" || $.eventName = "DeleteLogStream" || $.eventName = "PutRetentionPolicy" }' \
  --metric-transformations \
    "metricName=LogDeletionCount,\
metricNamespace=${NAMESPACE},\
metricValue=1,\
defaultValue=0" \
  --region "${AWS_REGION}" 2>/dev/null \
  || warn "CloudTrail log group not found — skipping log deletion filter"

echo ""

# ─── CloudWatch Alarms ────────────────────────────────────────────────────────

info "=== Creating CloudWatch Alarms ==="

# ── Alert 1: Brute Force Detection ───────────────────────────────────────────
# Trigger: 5+ failed logins in 15 minutes (Section 2.10.6)
# Period: 900 seconds = 15 minutes
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-BruteForceDetection" \
  --alarm-description "Alert 1 (Section 2.10.6): 5+ failed logins in 15 minutes. Possible brute force or credential stuffing attack." \
  --metric-name "FailedLoginCount" \
  --namespace "${NAMESPACE}" \
  --statistic "Sum" \
  --period 900 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --ok-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}"
success "Alarm: BruteForceDetection (≥5 failed logins / 15 min → SNS)"

# ── Alert 2: Authorization Failure Spike ─────────────────────────────────────
# Trigger: 10+ authorization failures in 5 minutes (Section 2.10.6)
# Period: 300 seconds = 5 minutes
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-AuthorizationFailureSpike" \
  --alarm-description "Alert 2 (Section 2.10.6): 10+ authorization failures in 5 minutes. Possible privilege escalation attempt or broken access control." \
  --metric-name "AuthorizationFailureCount" \
  --namespace "${NAMESPACE}" \
  --statistic "Sum" \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 10 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --ok-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}"
success "Alarm: AuthorizationFailureSpike (≥10 failures / 5 min → SNS)"

# ── Alert 3: Security Event ───────────────────────────────────────────────────
# Trigger: Any security.event logged (Section 2.10.6)
# Period: 60 seconds — immediate notification
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-SecurityEvent" \
  --alarm-description "Alert 3 (Section 2.10.6): A security event has been logged. Requires immediate review." \
  --metric-name "SecurityEventCount" \
  --namespace "${NAMESPACE}" \
  --statistic "Sum" \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}"
success "Alarm: SecurityEvent (any security.event / 1 min → SNS)"

# ── Bonus: Privilege Change ───────────────────────────────────────────────────
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-PrivilegeChange" \
  --alarm-description "A privilege change has been logged. Verify this was intentional." \
  --metric-name "PrivilegeChangeCount" \
  --namespace "${NAMESPACE}" \
  --statistic "Sum" \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}"
success "Alarm: PrivilegeChange (any privilege change / 1 min → SNS)"

# ── Bonus: Log Deletion ───────────────────────────────────────────────────────
aws cloudwatch put-metric-alarm \
  --alarm-name "${APP_NAME}-${ENV}-LogDeletion" \
  --alarm-description "A log group or stream has been deleted or modified. Possible evidence tampering (Section 2.10.7)." \
  --metric-name "LogDeletionCount" \
  --namespace "${NAMESPACE}" \
  --statistic "Sum" \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --treat-missing-data "notBreaching" \
  --alarm-actions "${SNS_TOPIC_ARN}" \
  --region "${AWS_REGION}" 2>/dev/null \
  || warn "Skipping LogDeletion alarm — CloudTrail metric filter not created"

echo ""

# ─── CloudWatch Insights Queries ─────────────────────────────────────────────
# Save useful queries for incident investigation.
# Access via: CloudWatch → Logs → Insights → Saved Queries

info "=== Saving CloudWatch Insights Queries ==="

save_query() {
  local name="$1"
  local query="$2"
  local log_groups="$3"

  aws logs put-query-definition \
    --name "${APP_NAME}/${name}" \
    --query-string "${query}" \
    --log-group-names ${log_groups} \
    --region "${AWS_REGION}" > /dev/null 2>/dev/null \
    && success "Saved query: ${name}" \
    || warn "Could not save query: ${name} (requires CloudWatch Logs Insights permissions)"
}

# Failed logins by IP — for brute force investigation
save_query \
  "Failed Logins by IP" \
  'fields @timestamp, ip, username, reason
| filter event = "auth.login.failure"
| stats count(*) as attempts by ip
| sort attempts desc
| limit 20' \
  "${LOG_GROUP_SECURITY}"

# Authorization failures by user — for insider threat investigation
save_query \
  "Authorization Failures by User" \
  'fields @timestamp, userId, resource, action
| filter event = "authz.failure"
| stats count(*) as failures by userId
| sort failures desc
| limit 20' \
  "${LOG_GROUP_SECURITY}"

# All activity for a specific user — for incident investigation
# Replace USER_ID with the actual user ID when running
save_query \
  "All Activity for User" \
  'fields @timestamp, event, resource, action, ip
| filter userId = "USER_ID"
| sort @timestamp desc
| limit 100' \
  "${LOG_GROUP_SECURITY}"

# Security events timeline
save_query \
  "Security Events Timeline" \
  'fields @timestamp, type, details, ip
| filter event = "security.event"
| sort @timestamp desc
| limit 50' \
  "${LOG_GROUP_SECURITY}"

echo ""

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "============================================================"
echo " Alerting Setup Complete"
echo "============================================================"
echo
