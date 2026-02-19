#!/bin/bash
# ============================================
# LET'S ENCRYPT AUTOMATED SETUP
# ============================================
# Referenced in: Vibe-Coded App Security Framework
# Chapter 2.5.1: HTTPS Everywhere
#
# This script automates Let's Encrypt certificate
# installation for Nginx or Apache
# ============================================

set -e  # Exit on error

# ============================================
# CONFIGURATION
# ============================================
DOMAIN="yourapp.com"
EMAIL="admin@yourapp.com"
WEBSERVER="nginx"  # or "apache"

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
# CHECK ROOT
# ============================================
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root (use sudo)"
    exit 1
fi

# ============================================
# INSTALL CERTBOT
# ============================================
print_info "Installing Certbot..."

if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    apt-get update
    apt-get install -y certbot
    
    if [ "$WEBSERVER" = "nginx" ]; then
        apt-get install -y python3-certbot-nginx
    elif [ "$WEBSERVER" = "apache" ]; then
        apt-get install -y python3-certbot-apache
    fi
elif [ -f /etc/redhat-release ]; then
    # CentOS/RHEL
    yum install -y certbot
    
    if [ "$WEBSERVER" = "nginx" ]; then
        yum install -y python3-certbot-nginx
    elif [ "$WEBSERVER" = "apache" ]; then
        yum install -y python3-certbot-apache
    fi
else
    print_error "Unsupported OS"
    exit 1
fi

print_success "Certbot installed"

# ============================================
# OBTAIN CERTIFICATE
# ============================================
print_info "Obtaining SSL certificate for $DOMAIN..."

if [ "$WEBSERVER" = "nginx" ]; then
    certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "$EMAIL"
elif [ "$WEBSERVER" = "apache" ]; then
    certbot --apache -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "$EMAIL"
else
    print_error "Invalid webserver: $WEBSERVER"
    exit 1
fi

print_success "SSL certificate obtained"

# ============================================
# TEST AUTO-RENEWAL
# ============================================
print_info "Testing auto-renewal..."
certbot renew --dry-run

print_success "Auto-renewal configured"

# ============================================
# VERIFY HTTPS
# ============================================
print_info "Verifying HTTPS..."

if curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" | grep -q "200\|301\|302"; then
    print_success "HTTPS is working"
else
    print_error "HTTPS verification failed"
    exit 1
fi

# ============================================
# SUMMARY
# ============================================
echo ""
echo "============================================"
echo "HTTPS SETUP COMPLETE"
echo "============================================"
echo "Domain: $DOMAIN"
echo "Certificate: /etc/letsencrypt/live/$DOMAIN/fullchain.pem"
echo "Private Key: /etc/letsencrypt/live/$DOMAIN/privkey.pem"
echo "Auto-renewal: Enabled (runs twice daily)"
echo ""
echo "Next steps:"
echo "1. Test your site: https://$DOMAIN"
echo "2. Check SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
echo "3. Consider HSTS preload: https://hstspreload.org/"
echo "============================================"
