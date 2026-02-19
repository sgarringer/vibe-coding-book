#!/bin/bash
# ============================================
# SSL/TLS CONFIGURATION TESTING
# ============================================
# Referenced in: Vibe-Coded App Security Framework
# Chapter 2.5.1: HTTPS Everywhere
#
# This script tests SSL/TLS configuration
# ============================================

set -e

# ============================================
# CONFIGURATION
# ============================================
DOMAIN="${1:-yourapp.com}"

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

# ============================================
# TESTS
# ============================================
echo "============================================"
echo "SSL/TLS CONFIGURATION TEST"
echo "Domain: $DOMAIN"
echo "============================================"
echo ""

# Test 1: HTTPS accessible
print_info "Test 1: HTTPS accessible..."
if curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" | grep -q "200\|301\|302"; then
    print_success "HTTPS is accessible"
else
    print_error "HTTPS is not accessible"
fi

# Test 2: HTTP redirects to HTTPS
print_info "Test 2: HTTP redirects to HTTPS..."
if curl -s -o /dev/null -w "%{redirect_url}" "http://$DOMAIN" | grep -q "https://"; then
    print_success "HTTP redirects to HTTPS"
else
    print_error "HTTP does not redirect to HTTPS"
fi

# Test 3: HSTS header present
print_info "Test 3: HSTS header present..."
if curl -s -I "https://$DOMAIN" | grep -i "strict-transport-security" > /dev/null; then
    print_success "HSTS header present"
else
    print_error "HSTS header missing"
fi

# Test 4: Certificate valid
print_info "Test 4: Certificate valid..."
if echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null | openssl x509 -noout -checkend 0 > /dev/null; then
    print_success "Certificate is valid"
else
    print_error "Certificate is invalid or expired"
fi

# Test 5: TLS 1.2 supported
print_info "Test 5: TLS 1.2 supported..."
if openssl s_client -connect "$DOMAIN:443" -tls1_2 < /dev/null 2>&1 | grep -q "Cipher"; then
    print_success "TLS 1.2 supported"
else
    print_error "TLS 1.2 not supported"
fi

# Test 6: TLS 1.3 supported
print_info "Test 6: TLS 1.3 supported..."
if openssl s_client -connect "$DOMAIN:443" -tls1_3 < /dev/null 2>&1 | grep -q "Cipher"; then
    print_success "TLS 1.3 supported"
else
    print_error "TLS 1.3 not supported (optional but recommended)"
fi

# Test 7: SSLv3 disabled
print_info "Test 7: SSLv3 disabled..."
if ! openssl s_client -connect "$DOMAIN:443" -ssl3 < /dev/null 2>&1 | grep -q "Cipher"; then
    print_success "SSLv3 disabled"
else
    print_error "SSLv3 enabled (insecure!)"
fi

# Test 8: Certificate expiration
print_info "Test 8: Certificate expiration..."
EXPIRY=$(echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

if [ $DAYS_LEFT -gt 30 ]; then
    print_success "Certificate expires in $DAYS_LEFT days"
elif [ $DAYS_LEFT -gt 0 ]; then
    print_error "Certificate expires in $DAYS_LEFT days (renew soon!)"
else
    print_error "Certificate expired!"
fi

# ============================================
# SUMMARY
# ============================================
echo ""
echo "============================================"
echo "ADDITIONAL CHECKS"
echo "============================================"
echo "Run these manual checks:"
echo ""
echo "1. SSL Labs Test:"
echo "   https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
echo "   (Should achieve A or A+ rating)"
echo ""
echo "2. Security Headers:"
echo "   https://securityheaders.com/?q=$DOMAIN"
echo "   (Should achieve A or A+ rating)"
echo ""
echo "3. Mixed Content:"
echo "   Open https://$DOMAIN in browser"
echo "   Check console for mixed content warnings"
echo ""
echo "============================================"
