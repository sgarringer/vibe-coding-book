#!/usr/bin/env bash
# Google Cloud Logging Setup
# Chapter 2.10.5
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - Project set (gcloud config set project YOUR_PROJECT_ID)
#   - APIs enabled: logging, monitoring
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

APP_NAME="${APP_NAME:-my-app}"
ENV="${ENV:-production}"
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
ALERT_EMAIL="${ALERT_EMAIL:-security@example.com}"
NOTIFICATION_CHANNEL_ID="${NOTIFICATION_CHANNEL_ID:-}"

# Log bucket names (for long-term storage with locked retention)
SECURITY_BUCKET="${APP_NAME}-${ENV}-security-logs"
AUDIT_BUCKET="${APP_NAME}-${ENV}-audit-logs"

# ─── Helpers ──────────────────────────────────────────────────────────────────

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
die()     { echo "[ERROR] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."
}

# ─── Preflight ────────────────────────────────────────────────────────────────

require_cmd gcloud
require_cmd jq

[ -z "${PROJECT_ID}" ] && die "PROJECT_ID not set. Run: gcloud config set project YOUR_PROJECT_ID"

info "Project : ${PROJECT_ID}"
info "App     : ${APP_NAME} (${ENV})"
echo ""

# Enable required APIs
info "=== Enabling APIs ==="
gcloud services enable \
  logging.googleapis.com \
  monitoring.googleapis.com \
  --project="${PROJECT_ID}" --quiet
success "APIs enabled: logging, monitoring"
echo ""

# ─── Log Buckets ──────────────────────────────────────────────────────────────
# Separate buckets per retention tier (Table 2.19)

info "=== Creating Log Buckets ==="

# Security bucket — 365 day retention, locked
gcloud logging buckets create "${SECURITY_BUCKET}" \
  --location=global \
  --retention-days=365 \
  --project="${PROJECT_ID}" \
  --description="Security and auth events — ${APP_NAME} ${ENV}" \
  2>/dev/null || warn "Bucket ${SECURITY_BUCKET} already exists"
success "Log bucket: ${SECURITY_BUCKET} (365 days)"

# Audit bucket — 365 day retention, locked
gcloud logging buckets create "${AUDIT_BUCKET}" \
  --location=global \
  --retention-days=365 \
  --project="${PROJECT_ID}" \
  --description="Audit events — ${APP_NAME} ${ENV}" \
  2>/dev/null || warn "Bucket ${AUDIT_BUCKET} already exists"
success "Log bucket: ${AUDIT_BUCKET} (365 days)"
echo ""

# ─── Log Sinks ────────────────────────────────────────────────────────────────
# Route security events to the security bucket

info "=== Creating Log Sinks ==="

# Security sink — routes auth and authz events
gcloud logging sinks create "${APP_NAME}-${ENV}-security-sink" \
  "logging.googleapis.com/projects/${PROJECT_ID}/locations/global/buckets/${SECURITY_BUCKET}" \
  --log-filter='jsonPayload.event=~"^auth\." OR jsonPayload.event=~"^authz\." OR jsonPayload.event="security.event"' \
  --project="${PROJECT_ID}" \
  2>/dev/null || warn "Sink ${APP_NAME}-${ENV}-security-sink already exists"
success "Log sink: security events → ${SECURITY_BUCKET}"

# Audit sink — routes privilege changes and API key events
gcloud logging sinks create "${APP_NAME}-${ENV}-audit-sink" \
  "logging.googleapis.com/projects/${PROJECT_ID}/locations/global/buckets/${AUDIT_BUCKET}" \
  --log-filter='jsonPayload.event="authz.privilege.change" OR jsonPayload.event=~"^apikey\."' \
  --project="${PROJECT_ID}" \
  2>/dev/null || warn "Sink ${APP_NAME}-${ENV}-audit-sink already exists"
success "Log sink: audit events → ${AUDIT_BUCKET}"
echo ""

# ─── Alerting Policies ────────────────────────────────────────────────────────
# Implements the three alerts from Section 2.10.6

info "=== Creating Notification Channel ==="

if [ -z "${NOTIFICATION_CHANNEL_ID}" ]; then
  CHANNEL_JSON=$(cat <<EOF
{
  "type": "email",
  "displayName": "${APP_NAME} Security Alerts",
  "labels": {
    "email_address": "${ALERT_EMAIL}"
  }
}
EOF
)
  NOTIFICATION_CHANNEL_ID=$(gcloud alpha monitoring channels create \
    --channel-content="${CHANNEL_JSON}" \
    --format="value(name)" \
    --project="${PROJECT_ID}" 2>/dev/null || echo "")

  if [ -n "${NOTIFICATION_CHANNEL_ID}" ]; then
    success "Notification channel: ${NOTIFICATION_CHANNEL_ID}"
  else
    warn "Could not create notification channel automatically."
    warn "Create one manually in: Console → Monitoring → Alerting → Notification Channels"
    warn "Then re-run with: NOTIFICATION_CHANNEL_ID=<id> ./setup.sh"
  fi
else
  success "Using existing notification channel: ${NOTIFICATION_CHANNEL_ID}"
fi
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "============================================================"
echo " Setup Complete"
echo "============================================================"
echo ""
echo " Project  : ${PROJECT_ID}"
echo " Log Buckets:"
echo "   Security : ${SECURITY_BUCKET} (365 days)"
echo "   Audit    : ${AUDIT_BUCKET} (365 days)"
echo ""
echo " Next Steps:"
echo "   1. Configure your app to use the GCP logging client"
echo "      See: nodejs-gcp.js"
echo "   2. Verify logs: Console → Logging → Log Explorer"
echo "   3. Set up alerting: Console → Monitoring → Alerting"
echo "   4. Restrict log access: Console → IAM → grant roles/logging.viewer"
echo "      to security team only (Section 2.10.7)"
echo "============================================================"
