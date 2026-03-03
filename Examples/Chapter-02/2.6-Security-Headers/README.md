# Security Headers — Complete Implementation Examples

Examples for Chapter 2.6 

Each example adds the following headers with recommended values:

| Header                    | Value                                        |
| ------------------------- | -------------------------------------------- |
| Content-Security-Policy   | default-src 'self'                           |
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload |
| X-Frame-Options           | DENY                                         |
| X-Content-Type-Options    | nosniff                                      |
| Referrer-Policy           | strict-origin-when-cross-origin              |
| Permissions-Policy        | geolocation=(), microphone=(), camera=()     |

## Testing Your Headers

After deploying, verify at:

- https://securityheaders.com
- https://observatory.mozilla.org

Target: Grade A on securityheaders.com

## Platform Examples

- [Node.js/Express](./nodejs-express/)
- [Python/Flask](./python-flask/)
- [Python/Django](./python-django/)
- [Nginx](./nginx/)
- [Apache](./apache/)
- [IIS](./iis/)
- [Cloudflare Workers](./cloudflare-workers/)
- [AWS CloudFront](./aws-cloudfront/)
