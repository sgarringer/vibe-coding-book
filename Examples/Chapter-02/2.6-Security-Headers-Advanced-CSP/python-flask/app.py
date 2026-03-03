import os
import json
import secrets
import logging

from flask import Flask, request, g, jsonify
from flask_talisman import Talisman

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ─── Nonce Generation ─────────────────────────────────────────────────────────
# Generate a fresh nonce before every request and store it on Flask's g object.
# Templates and the CSP header builder both read from g.csp_nonce.
# See Section 2.6.3.2.

@app.before_request
def generate_nonce():
    # 16 random bytes → URL-safe base64 string
    g.csp_nonce = secrets.token_urlsafe(16)


# ─── Talisman / CSP Configuration ────────────────────────────────────────────
# Talisman supports a callable for CSP values, which lets us inject the
# per-request nonce into the script-src directive.

def csp_policy():
    """Return the CSP directives dict for the current request."""
    return {
        'default-src': "'self'",
        # Include the per-request nonce in script-src.
        # See Section 2.6.3.2, Option 2.
        'script-src':  ["'self'", f"'nonce-{g.csp_nonce}'"],
        'style-src':   "'self'",
        'img-src':     ["'self'", 'data:', 'https:'],
        'connect-src': "'self'",
        'font-src':    "'self'",
        'object-src':  "'none'",
        'frame-src':   "'none'",
        'base-uri':    "'self'",
        'form-action': "'self'",
        'report-uri':  '/csp-violations',
    }


# Set report_only=True during Week 1–2 of rollout (Section 2.6.3.1).
# Switch to False when the policy is tuned.
talisman = Talisman(
    app,
    content_security_policy=csp_policy,
    content_security_policy_report_only=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
)


@app.after_request
def add_permissions_policy(response):
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=()'
    )
    return response


# ─── CSP Violation Reporting Endpoint ────────────────────────────────────────
# Browsers POST a JSON body here when a CSP violation occurs.
# Use this during Report-Only mode to understand what your policy blocks.

@app.route('/csp-violations', methods=['POST'])
def csp_violations():
    try:
        report = request.get_json(
            force=True,
            silent=True,
            content_type='application/csp-report'
        )
        if report:
            csp_report = report.get('csp-report', {})
            # In production, send this to your logging/SIEM system.
            logger.warning(
                'CSP Violation | blocked-uri=%s | violated-directive=%s | document-uri=%s',
                csp_report.get('blocked-uri'),
                csp_report.get('violated-directive'),
                csp_report.get('document-uri'),
            )
    except Exception as exc:
        logger.error('Failed to parse CSP report: %s', exc)

    # Always return 204 — browsers ignore the response body.
    return '', 204


# ─── Example Routes ───────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Demonstrates nonce usage in an inline script."""
    nonce = g.csp_nonce
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>CSP Nonce Demo</title>
    </head>
    <body>
      <h1>CSP Nonce Demo</h1>

      <!--
        ALLOWED: script tag carries the matching nonce.
        The nonce changes on every page load.
        See Section 2.6.3.2, Option 2.
      -->
      <script nonce="{nonce}">
        document.body.insertAdjacentHTML(
          'beforeend',
          '<p>✅ This inline script ran — it has the correct nonce.</p>'
        );
      </script>

      <!--
        BLOCKED: script tag has no nonce.
        The browser will refuse to execute this.
        See Section 2.6.3.2.
      -->
      <script>
        document.body.insertAdjacentHTML(
          'beforeend',
          '<p>❌ This should be blocked by CSP.</p>'
        );
      </script>

      <p>
        Open DevTools → Console to see the CSP violation for the blocked script.<br>
        Open DevTools → Network → this request → Response Headers to see the
        <code>Content-Security-Policy</code> header with the nonce value.
      </p>
    </body>
    </html>
    """


@app.route('/report-only-demo')
def report_only_demo():
    """
    Demonstrates Report-Only mode.
    Violations are logged but nothing is blocked.
    See Section 2.6.3.1.
    """
    nonce = g.csp_nonce

    # Build a report-only policy for this route.
    # In a real rollout you would set report_only=True globally (see above).
    report_only_policy = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"report-uri /csp-violations"
    )

    response = app.make_response(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>CSP Report-Only Demo</title>
    </head>
    <body>
      <h1>CSP Report-Only Mode</h1>
      <p>
        This page uses <code>Content-Security-Policy-Report-Only</code>.
        Violations are logged to <code>/csp-violations</code> but nothing is blocked.
        See Section 2.6.3.1.
      </p>

      <!-- This would be blocked in enforcing mode, but only reported here -->
      <script>
        document.body.insertAdjacentHTML(
          'beforeend',
          '<p>⚠️ This ran (report-only mode) — check server logs for the violation report.</p>'
        );
      </script>
    </body>
    </html>
    """)

    # Replace the enforcing header with a report-only header for this demo.
    response.headers.pop('Content-Security-Policy', None)
    response.headers['Content-Security-Policy-Report-Only'] = report_only_policy
    return response


if __name__ == '__main__':
    # Never use debug=True in production.
    app.run(host='0.0.0.0', port=5000, debug=False)
