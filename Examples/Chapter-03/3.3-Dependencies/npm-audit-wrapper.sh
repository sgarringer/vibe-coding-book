#!/usr/bin/env bash
# =============================================================================
# npm audit Wrapper Script
# Book Reference: Chapter 3, Section 3.3.2.2
# =============================================================================
# Features demonstrated:
#   - Threshold-based blocking
#   - JSON report generation
#   - CI/CD integration
#
# USAGE:
#   # Basic usage - fails on critical
#   ./npm-audit-wrapper.sh
#
#   # Custom thresholds
#   ./npm-audit-wrapper.sh --critical 0 --high 5 --moderate 20
#
#   # Output JSON report
#   ./npm-audit-wrapper.sh --output npm-audit-report.json
#
#   # Audit specific workspace
#   ./npm-audit-wrapper.sh --workspace packages/api
#
#   # Production dependencies only (skip devDependencies)
#   ./npm-audit-wrapper.sh --production
#
# EXIT CODES:
#   0 = All thresholds met
#   1 = One or more thresholds exceeded
#   2 = npm audit failed to run (missing package.json, etc.)
# =============================================================================

set -euo pipefail

# =============================================================================
# Default configuration
# Matches Example 3.6 thresholds from the book
# =============================================================================
CRITICAL_THRESHOLD=0
HIGH_THRESHOLD=5
MODERATE_THRESHOLD=20
LOW_THRESHOLD=999       # Effectively ignored per Table 3.4

OUTPUT_FILE=""
WORKSPACE=""
PRODUCTION_ONLY=false
VERBOSE=false
GENERATE_REPORT=true

# =============================================================================
# Color output
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'    # No color

info()    { echo -e "${CYAN}ℹ️  $*${NC}"; }
success() { echo -e "${GREEN}✅ $*${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $*${NC}"; }
error()   { echo -e "${RED}❌ $*${NC}"; }
bold()    { echo -e "${BOLD}$*${NC}"; }

# =============================================================================
# Argument parsing
# =============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --critical)
                CRITICAL_THRESHOLD="$2"
                shift 2
                ;;
            --high)
                HIGH_THRESHOLD="$2"
                shift 2
                ;;
            --moderate)
                MODERATE_THRESHOLD="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --workspace)
                WORKSPACE="$2"
                shift 2
                ;;
            --production)
                PRODUCTION_ONLY=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --no-report)
                GENERATE_REPORT=false
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                error "Unknown argument: $1"
                usage
                exit 2
                ;;
        esac
    done
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

npm audit wrapper with threshold-based CI/CD blocking.

OPTIONS:
    --critical N      Max critical vulnerabilities (default: $CRITICAL_THRESHOLD)
    --high N          Max high vulnerabilities (default: $HIGH_THRESHOLD)
    --moderate N      Max moderate vulnerabilities (default: $MODERATE_THRESHOLD)
    --output FILE     Save JSON report to FILE
    --workspace DIR   Run audit in specific workspace directory
    --production      Only audit production dependencies
    --verbose         Print all findings including low severity
    --no-report       Skip JSON report generation
    --help            Show this help message

EXIT CODES:
    0   All thresholds met
    1   One or more thresholds exceeded
    2   Audit failed to run

EXAMPLES:
    $(basename "$0") --critical 0 --high 3
    $(basename "$0") --output audit-report.json --production
    $(basename "$0") --workspace packages/api --verbose
EOF
}

# =============================================================================
# Prerequisite checks
# =============================================================================
check_prerequisites() {
    if ! command -v npm &>/dev/null; then
        error "npm is not installed or not in PATH"
        exit 2
    fi

    if ! command -v jq &>/dev/null; then
        error "jq is not installed. Install with: apt-get install jq"
        exit 2
    fi

    local audit_dir="${WORKSPACE:-.}"
    if [ ! -f "$audit_dir/package.json" ]; then
        error "No package.json found in $audit_dir"
        exit 2
    fi

    if [ ! -f "$audit_dir/package-lock.json" ] && \
       [ ! -f "$audit_dir/yarn.lock" ] && \
       [ ! -f "$audit_dir/npm-shrinkwrap.json" ]; then
        warning "No lockfile found. Run 'npm install' first for accurate results."
    fi
}

# =============================================================================
# Run npm audit
# =============================================================================
run_audit() {
    local audit_dir="${WORKSPACE:-.}"
    local audit_args=("--json")

    if [ "$PRODUCTION_ONLY" == "true" ]; then
        audit_args+=("--omit=dev")
        info "Auditing production dependencies only"
    fi

    info "Running npm audit in: $audit_dir"

    # Run audit - capture output regardless of exit code
    # npm audit exits 1 if vulnerabilities found, which would kill our script
    local raw_output
    if [ -n "$WORKSPACE" ]; then
        raw_output=$(cd "$audit_dir" && npm audit "${audit_args[@]}" 2>/dev/null) || true
    else
        raw_output=$(npm audit "${audit_args[@]}" 2>/dev/null) || true
    fi

    # Validate JSON output
    if ! echo "$raw_output" | jq empty 2>/dev/null; then
        error "npm audit produced invalid JSON output"
        error "Raw output: $raw_output"
        exit 2
    fi

    echo "$raw_output"
}

# =============================================================================
# Parse audit results
# npm audit JSON format differs between npm v6 and v7+
# =============================================================================
parse_results() {
    local audit_json="$1"

    # Detect npm version format
    local npm_version
    npm_version=$(npm --version | cut -d. -f1)

    local critical=0 high=0 moderate=0 low=0 info_count=0 total=0

    if [ "$npm_version" -ge 7 ]; then
        # npm v7+ format: vulnerabilities object
        critical=$(echo "$audit_json" | \
            jq '.metadata.vulnerabilities.critical // 0')
        high=$(echo "$audit_json" | \
            jq '.metadata.vulnerabilities.high // 0')
        moderate=$(echo "$audit_json" | \
            jq '.metadata.vulnerabilities.moderate // 0')
        low=$(echo "$audit_json" | \
            jq '.metadata.vulnerabilities.low // 0')
        info_count=$(echo "$audit_json" | \
            jq '.metadata.vulnerabilities.info // 0')
        total=$(echo "$audit_json" | \
            jq '.metadata.vulnerabilities.total // 0')
    else
        # npm v6 format: advisories object
        critical=$(echo "$audit_json" | \
            jq '[.advisories[] | select(.severity == "critical")] | length')
        high=$(echo "$audit_json" | \
            jq '[.advisories[] | select(.severity == "high")] | length')
        moderate=$(echo "$audit_json" | \
            jq '[.advisories[] | select(.severity == "moderate")] | length')
        low=$(echo "$audit_json" | \
            jq '[.advisories[] | select(.severity == "low")] | length')
        total=$((critical + high + moderate + low))
    fi

    # Export as global variables
    AUDIT_CRITICAL=$critical
    AUDIT_HIGH=$high
    AUDIT_MODERATE=$moderate
    AUDIT_LOW=$low
    AUDIT_INFO=$info_count
    AUDIT_TOTAL=$total
}

# =============================================================================
# Print findings summary
# =============================================================================
print_summary() {
    local audit_json="$1"

    echo ""
    bold "============================================"
    bold "  npm audit Results"
    bold "============================================"
    echo "  Critical : $AUDIT_CRITICAL  (threshold: $CRITICAL_THRESHOLD)"
    echo "  High     : $AUDIT_HIGH      (threshold: $HIGH_THRESHOLD)"
    echo "  Moderate : $AUDIT_MODERATE  (threshold: $MODERATE_THRESHOLD)"
    echo "  Low      : $AUDIT_LOW       (ignored)"
    echo "  Total    : $AUDIT_TOTAL"
    bold "============================================"

    # Print critical and high findings with context
    if [ "$AUDIT_CRITICAL" -gt 0 ] || [ "$AUDIT_HIGH" -gt 0 ]; then
        echo ""
        bold "Critical and High Findings:"
        echo ""

        local npm_version
        npm_version=$(npm --version | cut -d. -f1)

        if [ "$npm_version" -ge 7 ]; then
            echo "$audit_json" | jq -r '
                .vulnerabilities // {} |
                to_entries[] |
                select(.value.severity == "critical" or
                       .value.severity == "high") |
                "\n[\(.value.severity | ascii_upcase)] \(.key)
  Severity : \(.value.severity)
  Via      : \([.value.via[]? | if type == "object" then .title else . end] | join(", "))
  Fix      : \(.value.fixAvailable | if type == "object" then "npm install \(.name)@\(.version)" elif . == true then "npm audit fix" else "No fix available" end)"
            ' 2>/dev/null | head -80
        else
            echo "$audit_json" | jq -r '
                .advisories // {} |
                to_entries[] |
                select(.value.severity == "critical" or
                       .value.severity == "high") |
                "\n[\(.value.severity | ascii_upcase)] \(.value.module_name)
  Title    : \(.value.title)
  CVE      : \(.value.cves // [] | join(", "))
  Fix      : \(.value.recommendation)"
            ' 2>/dev/null | head -80
        fi
    fi

    if [ "$VERBOSE" == "true" ] && [ "$AUDIT_MODERATE" -gt 0 ]; then
        echo ""
        bold "Moderate Findings:"
        echo "$audit_json" | jq -r '
            .vulnerabilities // .advisories // {} |
            to_entries[] |
            select((.value.severity // "") == "moderate") |
            "  - \(.key): \(.value.via[0].title // .value.title // "N/A")"
        ' 2>/dev/null | head -30
    fi
}

# =============================================================================
# Generate JSON report
# =============================================================================
generate_report() {
    local audit_json="$1"
    local output_file="$2"
    local gate_status="$3"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    cat > "$output_file" << EOF
{
  "timestamp":   "$timestamp",
  "tool":        "npm-audit",
  "npm_version": "$(npm --version)",
  "gate_status": "$gate_status",
  "thresholds": {
    "critical": $CRITICAL_THRESHOLD,
    "high":     $HIGH_THRESHOLD,
    "moderate": $MODERATE_THRESHOLD
  },
  "findings": {
    "critical": $AUDIT_CRITICAL,
    "high":     $AUDIT_HIGH,
    "moderate": $AUDIT_MODERATE,
    "low":      $AUDIT_LOW,
    "total":    $AUDIT_TOTAL
  },
  "raw_audit": $(echo "$audit_json" | jq '.')
}
EOF

    info "Report saved to: $output_file"
}

# =============================================================================
# Evaluate thresholds and determine gate status
# =============================================================================
evaluate_gate() {
    local gate_status="pass"
    local failures=()

    if [ "$AUDIT_CRITICAL" -gt "$CRITICAL_THRESHOLD" ]; then
        gate_status="fail"
        failures+=("Critical: $AUDIT_CRITICAL (threshold: $CRITICAL_THRESHOLD)")
    fi

    if [ "$AUDIT_HIGH" -gt "$HIGH_THRESHOLD" ]; then
        gate_status="fail"
        failures+=("High: $AUDIT_HIGH (threshold: $HIGH_THRESHOLD)")
    fi

    if [ "$AUDIT_MODERATE" -gt "$MODERATE_THRESHOLD" ]; then
        # Moderate only warns per Table 3.4
        warning "Moderate threshold exceeded: $AUDIT_MODERATE (threshold: $MODERATE_THRESHOLD)"
        warning "Address these in the next sprint."
    fi

    if [ "$gate_status" == "fail" ]; then
        echo ""
        error "Security gate FAILED:"
        for failure in "${failures[@]}"; do
            error "  $failure"
        done
        echo ""
        info "Fix options:"
        info "  1. Run 'npm audit fix' for automatic fixes"
        info "  2. Run 'npm audit fix --force' for breaking changes (test carefully)"
        info "  3. Update specific packages: npm install <package>@latest"
        info "  4. For false positives, add to .npmrc: audit-level=high"
    else
        success "Security gate PASSED"
        success "All npm audit thresholds met"
    fi

    echo "$gate_status"
}

# =============================================================================
# Main execution
# =============================================================================
main() {
    parse_args "$@"
    check_prerequisites

    echo ""
    bold "npm audit Security Wrapper"
    bold "Book Reference: Chapter 3, Section 3.3.2.2"
    echo ""
    info "Thresholds: Critical=$CRITICAL_THRESHOLD High=$HIGH_THRESHOLD Moderate=$MODERATE_THRESHOLD"

    # Run audit
    local audit_json
    audit_json=$(run_audit)

    # Parse results
    parse_results "$audit_json"

    # Print summary
    print_summary "$audit_json"

    # Evaluate gate
    local gate_status
    gate_status=$(evaluate_gate)

    # Generate report if requested
    if [ "$GENERATE_REPORT" == "true" ] && [ -n "$OUTPUT_FILE" ]; then
        generate_report "$audit_json" "$OUTPUT_FILE" "$gate_status"
    fi

    # Exit with appropriate code for CI/CD
    if [ "$gate_status" == "fail" ]; then
        exit 1
    fi

    exit 0
}

main "$@"
