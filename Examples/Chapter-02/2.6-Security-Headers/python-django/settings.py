# settings.py — security header relevant sections only.
# Add these to your existing settings.py file.

# ─── Installed Apps ───────────────────────────────────────────────────────────
INSTALLED_APPS = [
    # ... your existing apps ...
    'csp',                      # django-csp
]

# ─── Middleware ───────────────────────────────────────────────────────────────
# Order matters. SecurityMiddleware should be first.
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'csp.middleware.CSPMiddleware',              # django-csp
    'django_permissions_policy.PermissionsPolicyMiddleware',  # permissions
    # ... your existing middleware ...
]

# ─── Strict-Transport-Security ────────────────────────────────────────────────
SECURE_HSTS_SECONDS = 31536000          # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True              # redirect HTTP → HTTPS

# ─── X-Content-Type-Options ───────────────────────────────────────────────────
SECURE_CONTENT_TYPE_NOSNIFF = True      # adds nosniff header

# ─── Referrer-Policy ──────────────────────────────────────────────────────────
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# ─── X-Frame-Options ──────────────────────────────────────────────────────────
X_FRAME_OPTIONS = 'DENY'

# ─── Content-Security-Policy (django-csp) ────────────────────────────────────
# Baseline policy — tune for your application.
# See chapter-02/headers/csp/ for full CSP examples.
CSP_DEFAULT_SRC  = ("'self'",)
CSP_SCRIPT_SRC   = ("'self'",)
CSP_STYLE_SRC    = ("'self'",)
CSP_IMG_SRC      = ("'self'", "data:", "https:")
CSP_CONNECT_SRC  = ("'self'",)
CSP_FONT_SRC     = ("'self'",)
CSP_OBJECT_SRC   = ("'none'",)
CSP_FRAME_SRC    = ("'none'",)
CSP_BASE_URI     = ("'self'",)
CSP_FORM_ACTION  = ("'self'",)

# Start in report-only mode, switch to False when policy is tuned.
# See Section 2.6.3.1
CSP_REPORT_ONLY  = False

# ─── Permissions-Policy (django-permissions-policy) ──────────────────────────
PERMISSIONS_POLICY = {
    'geolocation':  [],     # empty list = deny all
    'microphone':   [],
    'camera':       [],
}
