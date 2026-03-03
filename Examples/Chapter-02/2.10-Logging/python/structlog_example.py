"""
Structured Security Logging — Python with structlog
Chapter 2.10.3

Demonstrates:
- Structured JSON output
- Security event logging for all five critical event types (Section 2.10.1)
- Safe logging patterns (Section 2.10.2)
- Sensitive field redaction (Section 2.10.4)
"""

import os
import logging
import structlog

from flask import Flask, request, g

# ─── Sensitive Field Redaction ────────────────────────────────────────────────
# See Section 2.10.4.

SENSITIVE_FIELDS = {
    'password', 'passwd', 'pwd',
    'token', 'access_token', 'refresh_token', 'id_token',
    'api_key', 'apikey', 'apiKey',
    'secret', 'client_secret',
    'ssn', 'social_security',
    'credit_card', 'creditcard', 'card_number', 'cvv',
    'authorization',
    'cookie',
    'session_id', 'sessionid',
}


def redact_sensitive(logger, method, event_dict):
    """
    structlog processor that redacts sensitive fields before writing.
    Runs automatically on every log call.
    """
    def _redact(obj):
        if not isinstance(obj, dict):
            return obj
        return {
            k: '[REDACTED]' if k.lower() in SENSITIVE_FIELDS
            else _redact(v) if isinstance(v, dict)
            else v
            for k, v in obj.items()
        }

    return _redact(event_dict)


# ─── structlog Configuration ──────────────────────────────────────────────────

structlog.configure(
    processors=[
        # Add log level to every entry
        structlog.stdlib.add_log_level,

        # Add ISO 8601 timestamp (Section 2.10.3)
        structlog.processors.TimeStamper(fmt='iso'),

        # Redact sensitive fields before writing (Section 2.10.4)
        redact_sensitive,

        # Render as JSON (Section 2.10.3)
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

log = structlog.get_logger()

# Add service context to every log entry
log = log.bind(
    service=os.environ.get('SERVICE_NAME', 'my-app'),
    environment=os.environ.get('FLASK_ENV', 'development'),
)


# ─── Security Event Helpers ───────────────────────────────────────────────────

class SecurityLogger:
    """
    Wrapper for the five critical security event types (Section 2.10.1).
    Using named event strings makes logs queryable.
    """

    # Event Type 1: Authentication
    @staticmethod
    def login_success(user_id: str, ip: str, user_agent: str):
        log.info(
            'auth.login.success',
            event='auth.login.success',
            user_id=user_id,
            ip=ip,
            user_agent=user_agent,
        )

    @staticmethod
    def login_failure(username: str, ip: str, user_agent: str, reason: str):
        log.warning(
            'auth.login.failure',
            event='auth.login.failure',
            username=username,   # Log username, NOT password
            ip=ip,
            user_agent=user_agent,
            reason=reason,       # e.g. 'invalid_password', 'account_locked'
        )

    # Event Type 2: Authorization failure
    @staticmethod
    def authorization_failure(user_id: str, resource: str, action: str, ip: str):
        log.warning(
            'authz.failure',
            event='authz.failure',
            user_id=user_id,
            resource=resource,
            action=action,
            ip=ip,
        )

    # Event Type 3: Privilege change
    @staticmethod
    def privilege_change(
        actor_id: str, target_user_id: str,
        old_role: str, new_role: str, ip: str
    ):
        log.info(
            'authz.privilege.change',
            event='authz.privilege.change',
            actor_id=actor_id,
            target_user_id=target_user_id,
            old_role=old_role,
            new_role=new_role,
            ip=ip,
        )

    # Event Type 4: Password reset
    @staticmethod
    def password_reset_initiated(user_id: str, ip: str):
        log.info(
            'auth.password_reset.initiated',
            event='auth.password_reset.initiated',
            user_id=user_id,
            ip=ip,
            # NOT logged: reset token
        )

    @staticmethod
    def password_reset_completed(user_id: str, ip: str):
        log.info(
            'auth.password_reset.completed',
            event='auth.password_reset.completed',
            user_id=user_id,
            ip=ip,
        )

    # Event Type 5: API key lifecycle
    @staticmethod
    def api_key_created(user_id: str, key_id: str, ip: str):
        log.info(
            'apikey.created',
            event='apikey.created',
            user_id=user_id,
            key_id=key_id,   # Log the ID/reference, never the key value
            ip=ip,
        )

    @staticmethod
    def api_key_revoked(user_id: str, key_id: str, ip: str):
        log.info(
            'apikey.revoked',
            event='apikey.revoked',
            user_id=user_id,
            key_id=key_id,
            ip=ip,
        )

    # Generic security event (triggers Alert 3, Section 2.10.6)
    @staticmethod
    def security_event(event_type: str, details: dict, ip: str):
        log.warning(
            'security.event',
            event='security.event',
            type=event_type,
            details=details,
            ip=ip,
        )


security = SecurityLogger()

# ─── Request Logging Middleware ───────────────────────────────────────────────

app = Flask(__name__)


@app.before_request
def before_request():
    """Record request start time for duration calculation."""
    import time
    g.start_time = time.time()


@app.after_request
def log_request(response):
    """
    Log API calls: endpoint, method, status code, duration (Section 2.10.1).
    Does NOT log request body (Section 2.10.2).
    """
    import time
    duration_ms = round((time.time() - g.start_time) * 1000)

    log.info(
        'http.request',
        event='http.request',
        method=request.method,
        path=request.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
        ip=request.remote_addr,
        # NOT logged: request.get_json(), request.headers.get('Authorization')
    )
    return response


# ─── Example Routes ───────────────────────────────────────────────────────────

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    # password is in data.get('password') — we deliberately do NOT log it

    success = username == 'alice'

    if success:
        security.login_success('usr_abc123', request.remote_addr,
                               request.headers.get('User-Agent', ''))
        return {'message': 'Login successful'}, 200
    else:
        security.login_failure(username, request.remote_addr,
                               request.headers.get('User-Agent', ''),
                               'invalid_password')
        return {'message': 'Invalid credentials'}, 401


@app.route('/admin/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    user_role = request.headers.get('X-User-Role', '')

    if user_role != 'admin':
        security.authorization_failure(
            request.headers.get('X-User-Id', 'anonymous'),
            f'/admin/users/{user_id}',
            'DELETE',
            request.remote_addr,
        )
        return {'message': 'Forbidden'}, 403

    return {'message': 'User deleted'}, 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
