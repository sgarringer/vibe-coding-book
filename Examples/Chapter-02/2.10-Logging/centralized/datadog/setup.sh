#!/usr/bin/env bash
# Datadog Logging Setup
# Chapter 2.10.5
#
# Prerequisites:
#   - Datadog account and API key
#   - Datadog Agent installed on your server, OR
#   - Using HTTP log intake directly (serverless/containers)
#
# Usage:
#   export DD_API_KEY=your_api_key
#   export DD_APP_KEY=your_app_key   # required for creating monitors
#   chmod +x setup.sh
#   ./setup.sh

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

APP_NAME="${APP_NAME:-my-app}"
ENV="${ENV:-production}"
DD_SITE="${DD_SITE:-datadoghq.com}"
DD_API_KEY="${DD_API_KEY:-}"
DD_APP_KEY="${DD_APP_KEY:-}"
ALERT_EMAIL="${ALERT_EMAIL:-security@example.com}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
die()     { echo "[ERROR] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."
}

dd_api() {
  local method="$1"
  local endpoint="$2"
  local data="${3:-}"

  curl -s -X "${method}" \
    "https://api.${DD_SITE}/api/v1/${endpoint}" \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    -H "Content-Type: application/json" \
    ${data:+-d "${data}"}
}

# ─── Preflight ────────────────────────────────────────────────────────────────

require_cmd curl
require_cmd jq

[ -z "${DD_API_KEY}" ] && die "DD_API_KEY is required. Export it before running."
[ -z "${DD_APP_KEY}" ] && die "DD_APP_KEY is required. Export it before running."

info "Verifying Datadog credentials..."
VALIDATE=$(dd_api GET "validate")
echo "${VALIDATE}" | jq -e '.valid == true' > /dev/null \
  || die "Invalid Datadog API key. Check DD_API_KEY."
success "Datadog credentials valid"
echo ""

# ─── Log Indexes ──────────────────────────────────────────────────────────────
# Datadog routes logs to indexes based on filters.
# Security and audit logs get longer retention.

info "=== Configuring Log Indexes ==="
info "Log indexes must be configured in the Datadog UI:"
info "  Logs → Configuration → Indexes"
info ""
info "Recommended indexes:"
info "  security-logs  — filter: service:${APP_NAME} @event:(auth.* OR authz.* OR security.event OR apikey.*)"
info "                   retention: 15 days (or your plan maximum)"
info "  app-logs       — filter: service:${APP_NAME}"
info "                   retention: 7 days"
echo ""

# ─── Monitors (Alerts) ────────────────────────────────────────────────────────
# Implements the three alerts from Section 2.10.6

info "=== Creating Datadog Monitors ==="

# Alert 1: Brute force detection
# 5+ failed logins in 15 minutes
MONITOR_1=$(cat <<EOF
{
  "name": "[${APP_NAME}] Brute Force Detection",
  "type": "log alert",
  "query": "logs(\"service:${APP_NAME} @event:auth.login.failure\").index(\"*\").rollup(\"count\").last(\"15m\") >= 5",
  "message": "Alert 1 (Section 2.10.6): 5 or more failed login attempts detected in the last 15 minutes.\n\nService: ${APP_NAME}\nEnvironment: ${ENV}\n\nInvestigate: https://app.${DD_SITE}/logs?query=service:${APP_NAME}%20%40event:auth.login.failure\n\nNotify: @${ALERT_EMAIL}",
  "tags": ["app:${APP_NAME}", "env:${ENV}", "security:brute-force"],
  "options": {
    "notify_no_data": false,
    "renotify_interval": 60,
    "thresholds": { "critical": 5 }
  }
}
EOF
)

RESULT=$(dd_api POST "monitor" "${MONITOR_1}")
MONITOR_1_ID=$(echo "${RESULT}" | jq -r '.id // empty')
[ -n "${MONITOR_1_ID}" ] \
  && success "Monitor created: BruteForceDetection (ID: ${MONITOR_1_ID})" \
  || warn "Failed to create BruteForceDetection monitor: $(echo "${RESULT}" | jq -r '.errors // .error // .')"

# Alert 2: Authorization failure spike
# 10+ authorization failures in 5 minutes
MONITOR_2=$(cat <<EOF
{
  "name": "[${APP_NAME}] Authorization Failure Spike",
  "type": "log alert",
  "query": "logs(\"service:${APP_NAME} @event:authz.failure\").index(\"*\").rollup(\"count\").last(\"5m\") >= 10",
  "message": "Alert 2 (Section 2.10.6): 10 or more authorization failures detected in the last 5 minutes.\n\nService: ${APP_NAME}\nEnvironment: ${ENV}\n\nInvestigate: https://app.${DD_SITE}/logs?query=service:${APP_NAME}%20%40event:authz.failure\n\nNotify: @${ALERT_EMAIL}",
  "tags": ["app:${APP_NAME}", "env:${ENV}", "security:authz"],
  "options": {
    "notify_no_data": false,
    "renotify_interval": 30,
    "thresholds": { "critical": 10 }
  }
}
EOF
)

RESULT=$(dd_api POST "monitor" "${MONITOR_2}")
MONITOR_2_ID=$(echo "${RESULT}" | jq -r '.id // empty')
[ -n "${MONITOR_2_ID}" ] \
  && success "Monitor created: AuthorizationFailureSpike (ID: ${MONITOR_2_ID})" \
  || warn "Failed to create AuthorizationFailureSpike monitor: $(echo "${RESULT}" | jq -r '.errors // .error // .')"

# Alert 3: Any security event
MONITOR_3=$(cat <<EOF
{
  "name": "[${APP_NAME}] Security Event Detected",
  "type": "log alert",
  "query": "logs(\"service:${APP_NAME} @event:security.event\").index(\"*\").rollup(\"count\").last(\"1m\") >= 1",
  "message": "Alert 3 (Section 2.10.6): A security event has been logged.\n\nService: ${APP_NAME}\nEnvironment: ${ENV}\n\nInvestigate: https://app.${DD_SITE}/logs?query=service:${APP_NAME}%20%40event:security.event\n\nNotify: @${ALERT_EMAIL}",
  "tags": ["app:${APP_NAME}", "env:${ENV}", "security:event"],
  "options": {
    "notify_no_data": false,
    "renotify_interval": 15,
    "thresholds": { "critical": 1 }
  }
}
EOF
)

RESULT=$(dd_api POST "monitor" "${MONITOR_3}")
MONITOR_3_ID=$(echo "${RESULT}" | jq -r '.id // empty')
[ -n "${MONITOR_3_ID}" ] \
  && success "Monitor created: SecurityEventDetected (ID: ${MONITOR_3_ID})" \
  || warn "Failed to create SecurityEventDetected monitor: $(echo "${RESULT}" | jq -r '.errors // .error // .')"

echo ""

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "============================================================"
echo " Setup Complete"
echo "============================================================"
echo ""
echo " Monitors created in Datadog:"
[ -n "${MONITOR_1_ID:-}" ] && echo "   BruteForceDetection       — ID: ${MONITOR_1_ID}"
[ -n "${MONITOR_2_ID:-}" ] && echo "   AuthorizationFailureSpike — ID: ${MONITOR_2_ID}"
[ -n "${MONITOR_3_ID:-}" ] && echo "   SecurityEventDetected     — ID: ${MONITOR_3_ID}"
echo ""
echo " Next Steps:"
echo "   1. Configure log indexes in Datadog UI (see above)"
echo "   2. Configure your app to ship logs — see nodejs-datadog.js"
echo "   3. Verify logs: https://app.${DD_SITE}/logs"
echo "   4. Review monitors: https://app.${DD_SITE}/monitors/manage"
echo "============================================================"
