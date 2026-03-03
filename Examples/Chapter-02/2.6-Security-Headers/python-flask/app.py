from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# ─── Option 1: Talisman Defaults (quickest) ───────────────────────────────────
# Talisman's defaults cover most headers with sensible values.
# Uncomment this and remove Option 2 if you want the simplest setup.
#
# Talisman(app)

# ─── Option 2: Explicit Configuration (recommended) ──────────────────────────
# Explicitly configure each header so the values are visible and intentional.

# Baseline CSP — tune for your application.
# See chapter-02/headers/csp/ for full CSP examples.
csp = {
    'default-src': "'self'",
    'script-src':  "'self'",
    'style-src':   "'self'",
    'img-src':     ["'self'", 'data:', 'https:'],
    'connect-src': "'self'",
    'font-src':    "'self'",
    'object-src':  "'none'",
    'frame-src':   "'none'",
    'base-uri':    "'self'",
    'form-action': "'self'",
}

Talisman(
    app,

    # Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,

    # X-Frame-Options: DENY
    frame_options='DENY',

    # X-Content-Type-Options: nosniff (always on in Talisman)

    # Referrer-Policy: strict-origin-when-cross-origin
    referrer_policy='strict-origin-when-cross-origin',

    # Content-Security-Policy
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],  # enables nonce support
)


# Permissions-Policy — not yet covered by Talisman, added via after_request
@app.after_request
def add_permissions_policy(response):
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=()'
    )
    return response


# ─── Example Route ────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return """
    <html>
      <head><title>Security Headers Demo</title></head>
      <body>
        <h1>Security Headers Active</h1>
        <p>Open DevTools → Network → click this request → Response Headers
           to verify all headers are present.</p>
      </body>
    </html>
    """


if __name__ == '__main__':
    # Never use debug=True in production
    app.run(host='0.0.0.0', port=5000, debug=False)
