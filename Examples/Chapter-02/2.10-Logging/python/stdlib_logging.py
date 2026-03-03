"""
Structured Security Logging — Python with stdlib logging + python-json-logger
Chapter 2.10.3

Use this if you cannot add structlog as a dependency.
python-json-logger adds JSON formatting to the standard library logger.
"""

import os
import json
import logging
import time

from pythonjsonlogger import jsonlogger
from flask import Flask, request, g

# ─── Sensitive Field Redaction ────────────────────────────────────────────────

SENSITIVE_FIELDS = {
    'password', 'passwd', 'token', 'api_key', 'apikey',
    'secret', 'ssn', 'credit_card', 'cvv', 'authorization', 'cookie',
}


class RedactingFilter(logging.Filter):
    """
    Logging filter that redacts sensitive fields from log records.
    Attached to the handler so it runs on every log entry.
    See Section 2.10.4.
    """

    def _redact(self, obj):
        if not isinstance(obj, dict):
            return obj
        return {
            k: '[REDACTED]' if k.lower() in SENSITIVE_FIELDS
            else self._redact(v) if isinstance(v, dict)
            else v
            for k, v in obj.items()
        }

    def filter(self, record):
        # Redact the message args if they are a dict
        if isinstance(record.args, dict):
            record.args = self._redact(record.args)
        # Redact any extra fields attached to the record
        for attr in list(vars(record).keys()):
            val = getattr(record, attr)
            if isinstance(val, dict):
                setattr(record, attr, self._redact(val))
        return True


# ─── Logger Setup ─────────────────────────────────────────────────────────────

def create_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())

    handler = logging.StreamHandler()

    # JSON formatter — outputs structured logs (Section 2.10.3)
    formatter = jsonlogger.JsonFormatter(
        fmt='%(asctime)s %(levelname)s %(name)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%SZ',
        rename_fields={'asctime': 'timestamp', 'levelname': 'level'},
    )
    handler.setFormatter(formatter)
    handler.addFilter(RedactingFilter())

    logger.addHandler(handler)
    return logger


logger = create_logger('security')


# ─── Security Event Helpers ───────────────────────────────────────────────────

class SecurityLogger:

    @staticmethod
    def _log(level: str, event: str, **kwargs):
        extra = {
            'event': event,
            'service': os.environ.get('SERVICE_NAME', 'my-app'),
            **kwargs,
        }
        getattr(logger, level)(event, extra=extra)

    # Event Type 1: Authentication
    @staticmethod
    def login_success(user_id, ip, user_agent):
        SecurityLogger._log('info', 'auth.login.success',
                            user_id=user_id, ip=ip, user_agent=user_agent)

    @staticmethod
    def login_failure(username, ip, user_agent, reason):
        SecurityLogger._log('warning', 'auth.login.failure',
                            username=username, ip=ip,
                            user_agent=user_agent, reason=reason)

    # Event Type 2: Authorization failure
    @staticmethod
    def authorization_failure(user_id, resource, action, ip):
        SecurityLogger._log('warning', 'authz.failure',
                            user_id=user_id, resource=resource,
                            action=action, ip=ip)

    # Event Type 3: Privilege change
    @staticmethod
    def privilege_change(actor_id, target_user_id, old_role, new_role, ip):
        SecurityLogger._log('info', 'authz.privilege.change',
                            actor_id=actor_id, target_user_id=target_user_id,
                            old_role=old_role, new_role=new_role, ip=ip)

    # Event Type 4: Password reset
    @staticmethod
    def password_reset_initiated(user_id, ip):
        SecurityLogger._log('info', 'auth.password_reset.initiated',
                            user_id=user_id, ip=ip)

    @staticmethod
    def password_reset_completed(user_id, ip):
        SecurityLogger._log('info', 'auth.password_reset.completed',
                            user_id=user_id, ip=ip)

    # Event Type 5: API key lifecycle
    @staticmethod
    def api_key_created(user_id, key_id, ip):
        SecurityLogger._log('info', 'apikey.created',
                            user_id=user_id, key_id=key_id, ip=ip)

    @staticmethod
    def api_key_revoked(user_id, key_id, ip):
        SecurityLogger._log('info', 'apikey.revoked',
                            user_id=user_id, key_id=key_id, ip=ip)

    @staticmethod
    def security_event(event_type, details, ip):
        SecurityLogger._log('warning', 'security.event',
                            type=event_type, details=details, ip=ip)


security = SecurityLogger()

app = Flask(__name__)


@app.before_request
def before_request():
    g.start_time = time.time()


@app.after_request
def log_request(response):
    duration_ms = round((time.time() - g.start_time) * 1000)
    logger.info('http.request', extra={
        'event': 'http.request',
        'method': request.method,
        'path': request.path,
        'status_code': response.status_code,
        'duration_ms': duration_ms,
        'ip': request.remote_addr,
    })
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
