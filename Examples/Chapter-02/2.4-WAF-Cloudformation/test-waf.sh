#!/bin/bash
# ============================================
# AWS WAF TESTING SCRIPT
# ============================================
# Tests WAF rules by sending various attack patterns
# Usage: ./test-waf.sh <url>
# Example: ./test-waf.sh https://yourapp.com
# ============================================

set -e

# ============================================
# COLORS
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

test_request() {
    local test_name=$1
    local url=$2
    local expected_status=$3
    
    print_info "Testing: $test_name"
    
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>&1 || echo "000")
    
    if [ "$status" = "$expected_status" ]; then
        print_success "PASS - Got expected status $status"
        return 0
    else
        print_error "FAIL - Expected $expected_status, got $status"
        return 1
    fi
}

# ============================================
# VALIDATE ARGUMENTS
# ============================================
if [ $# -ne 1 ]; then
    print_error "Usage: $0 <url>"
    echo "Example: $0 https://yourapp.com"
    exit 1
fi

BASE_URL=$1

# Remove trailing slash
BASE_URL=${BASE_URL%/}

echo "============================================"
echo "AWS WAF TESTING SUITE"
echo "============================================"
echo "Target: $BASE_URL"
echo "============================================"
echo ""

PASSED=0
FAILED=0

# ============================================
# TEST 1: NORMAL REQUEST (SHOULD PASS)
# ============================================
if test_request "Normal request" "$BASE_URL/" "200"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 2: SQL INJECTION - UNION SELECT
# ============================================
if test_request "SQL Injection (UNION SELECT)" \
    "$BASE_URL/api/users?id=1%20UNION%20SELECT%20*%20FROM%20users" "403"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 3: SQL INJECTION - OR 1=1
# ============================================
if test_request "SQL Injection (OR 1=1)" \
    "$BASE_URL/api/users?id=1'%20OR%20'1'='1" "403"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 4: SQL INJECTION - DROP TABLE
# ============================================
if test_request "SQL Injection (DROP TABLE)" \
    "$BASE_URL/api/users?id=1;%20DROP%20TABLE%20users" "403"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 5: XSS - SCRIPT TAG
# ============================================
if test_request "XSS (script tag)" \
    "$BASE_URL/search?q=%3Cscript%3Ealert('xss')%3C/script%3E" "403"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 6: XSS - IMG ONERROR
# ============================================
if test_request "XSS (img onerror)" \
    "$BASE_URL/search?q=%3Cimg%20src=x%20onerror=alert('xss')%3E" "403"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 7: PATH TRAVERSAL - ../
# ============================================
if test_request "Path Traversal (../)" \
    "$BASE_URL/files?path=../../etc/passwd" "403"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 8: PATH TRAVERSAL - /etc/passwd
# ============================================
if test_request "Path Traversal (/etc/passwd)" \
    "$BASE_URL/files?path=/etc/passwd" "403"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 9: RATE LIMITING - LOGIN
# ============================================
print_info "Testing: Rate limiting (login endpoint)"
print_info "Sending 15 requests to /login..."

BLOCKED=0
for i in {1..15}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -d "username=test&password=wrong" 2>&1 || echo "000")
    
    if [ "$status" = "403" ]; then
        ((BLOCKED++))
    fi
    
    sleep 0.5
done

if [ $BLOCKED -gt 0 ]; then
    print_success "PASS - Rate limiting triggered ($BLOCKED requests blocked)"
    ((PASSED++))
else
    print_error "FAIL - Rate limiting not triggered"
    ((FAILED++))
fi
echo ""

# ============================================
# TEST 10: USER AGENT - SQLMAP
# ============================================
if test_request "Bad User Agent (sqlmap)" \
    "$BASE_URL/" "403" \
    -H "User-Agent: sqlmap/1.0"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# ============================================
# SUMMARY
# ============================================
echo "============================================"
echo "TEST SUMMARY"
echo "============================================"
echo "Total Tests: $((PASSED + FAILED))"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "============================================"

if [ $FAILED -eq 0 ]; then
    print_success "All tests passed!"
    exit 0
else
    print_error "Some tests failed. Check WAF configuration."
    exit 1
fi
