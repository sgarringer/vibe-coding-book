# HTTPS Configuration Examples

Complete HTTPS setup guides for Nginx, Apache, IIS, and cloud providers.

Referenced in Chapter 2.5.1 of the Vibe-Coded App Security Framework.

## Why HTTPS is Non-Negotiable

- Prevents eavesdropping and session hijacking
- Prevents man-in-the-middle attacks
- Required for modern browser features (Service Workers, geolocation, etc.)
- Required for SEO (Google penalizes HTTP sites)
- Required for compliance (PCI-DSS, HIPAA, GDPR, etc.)

## Quick Start

### 1. Obtain SSL/TLS Certificate

**Option A: Let's Encrypt (Free, Automated)**

```bash
# Install Certbot
sudo apt-get update
sudo apt-get install certbot

# For Nginx
sudo certbot --nginx -d yourapp.com -d www.yourapp.com

# For Apache
sudo certbot --apache -d yourapp.com -d www.yourapp.com

# Auto-renewal (runs twice daily)
sudo certbot renew --dry-run
```
**Option B: Commercial Certificate**

- Purchase from: DigiCert, Sectigo, GlobalSign
- Generate CSR on your server
- Install certificate files

**Option C: Cloud Provider**

- AWS Certificate Manager (ACM) - Free
- Azure App Service Certificates
- Google-managed SSL certificates

### 2. Configure Web Server

See configuration files in this directory:

- nginx.conf - Nginx configuration
- apache.conf - Apache configuration
- iis-web.config - IIS configuration

### 3. Test Configuration

```# Test SSL/TLS configuration
https://www.ssllabs.com/ssltest/analyze.html?d=yourapp.com

# Should achieve A+ rating
```

## Files In This Directory

- nginx.conf - Complete Nginx HTTPS configuration
- apache.conf - Complete Apache HTTPS configuration
- iis-web.config - IIS HTTPS configuration
- cloudflare-setup.md - Cloudflare SSL/TLS setup
- aws-alb-https.md - AWS Application Load Balancer HTTPS
- azure-app-service-https.md - Azure App Service HTTPS
- gcp-load-balancer-https.md - Google Cloud Load Balancer HTTPS
- lets-encrypt-setup.sh - Automated Let's Encrypt setup script
- ssl-test.sh - SSL/TLS configuration testing script

## Security Best Practices

### TLS Version

- Use TLS 1.2 and TLS 1.3 only
- Disable TLS 1.0 and TLS 1.1 (deprecated)
- Disable SSLv2 and SSLv3 (insecure)

### Cipher Suites

- Use strong cipher suites only
- Prefer ECDHE (forward secrecy)
- Disable weak ciphers (RC4, DES, 3DES, MD5)

### HSTS (HTTP Strict Transport Security)

- Enable HSTS header
- Set max-age to at least 1 year (31536000 seconds)
- Include subdomains
- Consider HSTS preload

### Certificate
- Use 2048-bit or 4096-bit RSA keys
- Or use 256-bit ECDSA keys (faster)
- Include intermediate certificates
- Set up auto-renewal (Let's Encrypt)

## Common Issues

### Mixed Content Warnings

Problem: Page loads over HTTPS but includes HTTP resources

**Solution:**

```<!-- Bad: HTTP resource -->
<script src="http://example.com/script.js"></script>

<!-- Good: HTTPS resource -->
<script src="https://example.com/script.js"></script>

<!-- Better: Protocol-relative URL -->
<script src="//example.com/script.js"></script>
```

### Certificate Chain Issues

Problem: Intermediate certificates not installed

**Solution:**

```# Nginx: Concatenate certificates
cat yourapp.com.crt intermediate.crt > fullchain.pem

# Apache: Use SSLCertificateChainFile directive
SSLCertificateChainFile /path/to/intermediate.crt
```

## Redirect Loops

Problem: HTTP → HTTPS redirect causes infinite loop

**Solution:**

```# Check if already HTTPS before redirecting
if ($scheme != "https") {
    return 301 https://$host$request_uri;
}
```

## Testing Checklist
- [ ] HTTPS loads without warnings
- [ ] HTTP redirects to HTTPS
- [ ] HSTS header present
- [ ] SSL Labs test shows A or A+
- [ ] No mixed content warnings
- [ ] Certificate valid and not expired
- [ ] Certificate chain complete
- [ ] TLS 1.2 and 1.3 enabled
- [ ] Weak ciphers disabled
- [ ] Auto-renewal configured (Let's Encrypt)

## Monitoring

### Certificate Expiration

```# Check certificate expiration
echo | openssl s_client -servername yourapp.com -connect yourapp.com:443 2>/dev/null | openssl x509 -noout -dates

# Set up monitoring (cron job)
0 0 * * * /path/to/check-cert-expiry.sh
```

### SSL/TLS Health

- Use SSL Labs API for automated testing
- Monitor certificate expiration (30 days warning)
- Alert on TLS configuration changes

## Related

- Chapter 2.5.1: HTTPS Everywhere
- Chapter 2.5.2: Secure Cookie Configuration
- Chapter 4.2: Cloud Provider Security