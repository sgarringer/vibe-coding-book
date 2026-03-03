# middleware.py
# Optional custom middleware if you prefer not to use third-party packages.
# If you use django-csp and django-permissions-policy (recommended),
# you do not need this file.


class SecurityHeadersMiddleware:
    """
    Adds security headers not covered by Django's built-in SecurityMiddleware.
    Use this only if you cannot install django-csp or django-permissions-policy.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Content-Security-Policy
        # Baseline policy — tune for your application.
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # Permissions-Policy
        response['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=()'
        )

        return response
