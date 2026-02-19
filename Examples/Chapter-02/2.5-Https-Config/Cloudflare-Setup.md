# Cloudflare SSL/TLS Setup

Cloudflare provides free SSL/TLS certificates and automatic HTTPS redirects.

Referenced in Chapter 2.5.1 of the Vibe-Coded App Security Framework.

## Prerequisites

- Domain registered
- Access to domain DNS settings
- Cloudflare account (free)

## Setup Steps

### 1. Add Site to Cloudflare

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Click "Add a Site"
3. Enter your domain: `yourapp.com`
4. Select Free plan
5. Click "Add Site"

### 2. Update Nameservers

Cloudflare will provide two nameservers:

```
ns1.cloudflare.com
ns2.cloudflare.com
```

Update your domain's nameservers at your registrar:

- GoDaddy: Domain Settings → Nameservers → Change
- Namecheap: Domain List → Manage → Nameservers → Custom DNS
- Google Domains: DNS → Name servers → Use custom name servers

**Wait 24-48 hours for DNS propagation.**

### 3. Configure SSL/TLS

1. Go to **SSL/TLS** tab
2. Set SSL/TLS encryption mode:

   - **Full (strict)** - Recommended (requires valid certificate on origin)
   - **Full** - Encrypts but doesn't validate origin certificate
   - **Flexible** - Not recommended (HTTP to origin)
3. Enable **Always Use HTTPS**:

   - SSL/TLS → Edge Certificates
   - Toggle "Always Use HTTPS" to ON
4. Enable **HSTS**:

   - SSL/TLS → Edge Certificates
   - Click "Enable HSTS"
   - Settings:
     - Max Age: 6 months (15768000 seconds)
     - Include subdomains: Yes
     - Preload: Yes (optional)
     - No-Sniff header: Yes
5. Set **Minimum TLS Version**:

   - SSL/TLS → Edge Certificates
   - Minimum TLS Version: TLS 1.2

### 4. Configure Page Rules (Optional)

Create page rule to force HTTPS:

1. Go to **Rules** → **Page Rules**
2. Click "Create Page Rule"
3. URL: `http://*yourapp.com/*`
4. Setting: "Always Use HTTPS"
5. Save and Deploy

### 5. Enable HTTP/2 and HTTP/3

1. Go to **Network** tab
2. Enable **HTTP/2**
3. Enable **HTTP/3 (with QUIC)**

### 6. Configure Security Headers

1. Go to **Rules** → **Transform Rules**
2. Click "Create Rule"
3. Rule name: "Security Headers"
4. When incoming requests match: All incoming requests
5. Then modify response headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload 
X-Frame-Options: SAMEORIGIN 
X-Content-Type-Options: nosniff 
X-XSS-Protection: 1; mode=block 
Referrer-Policy: strict-origin-when-cross-origin 
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Verification

### Test HTTPS

```
bash
curl -I https://yourapp.com
```

Should return:

- Status: 200 OK
- ``strict-transport-security`` header present

### Test HTTP Redirect

```
curl -I http://yourapp.com
```

Should return:

- Status: 301 Moved Permanently
- Location: https://yourapp.com

### SSL Labs Test

https://www.ssllabs.com/ssltest/analyze.html?d=yourapp.com

Should achieve **A** or **A+** rating.

## Origin Server Configuration

### Option 1: Cloudflare Origin Certificate (Recommended)

1. Go to SSL/TLS → Origin Server
2. Click "Create Certificate"
3. Generate certificate (15-year validity)
4. Install on your origin server:

**Nginx:**

```
ssl_certificate /etc/ssl/cloudflare/cert.pem;
ssl_certificate_key /etc/ssl/cloudflare/key.pem;
```

**Apache:**

```
SSLCertificateFile /etc/ssl/cloudflare/cert.pem
SSLCertificateKeyFile /etc/ssl/cloudflare/key.pem
```

### Option 2: Let's Encrypt

Use Let's Encrypt on your origin server:

```
sudo certbot --nginx -d yourapp.com
```

Set Cloudflare SSL mode to Full (strict).

## Troubleshooting

### Redirect Loop

**Problem:** Infinite redirect between HTTP and HTTPS

**Solution:**

- Check Cloudflare SSL mode (should be Full or Full (strict))
- Ensure origin server is configured for HTTPS
- Check for conflicting redirect rules

### Mixed Content Warnings

**Problem:** Page loads over HTTPS but includes HTTP resources

**Solution:**

1. Enable Automatic HTTPS Rewrites:
   * SSL/TLS → Edge Certificates
   * Toggle "Automatic HTTPS Rewrites" to ON
2. Update hardcoded HTTP URLs in your code:
    ```
    <!-- Bad -->

    <script src="http://example.com/script.js"></script>

    <!-- Good -->

    <script src="https://example.com/script.js"></script>
    ```

### Certificate Errors

**Problem:** "Your connection is not private" error

**Solution:**

- Wait for DNS propagation (24-48 hours)
- Check Cloudflare SSL mode
- Verify origin certificate is valid
- Clear browser cache

### Advanced: HSTS Preload

To add your domain to the HSTS preload list:

1. Enable HSTS in Cloudflare (see step 3.4 above)
2. Visit https://hstspreload.org/
3. Enter your domain
4. Submit for preload
   **Warning:** This is permanent and cannot be easily undone.

## Monitoring

### Certificate Expiration

Cloudflare automatically renews certificates. No action needed.

### SSL/TLS Health

Monitor in Cloudflare Dashboard:

- Analytics → Security
- Check for SSL/TLS errors

## Related

Chapter 2.5.1: HTTPS Everywhere
Chapter 2.4.2: WAF Deployment (Cloudflare)
Cloudflare Docs: https://developers.cloudflare.com/ssl/
