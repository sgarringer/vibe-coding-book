/**
 * Structured Security Logging — Node.js with Winston
 * Chapter 2.10.3
 *
 * Demonstrates:
 * - Structured JSON output
 * - Security event logging for all five critical event types (Section 2.10.1)
 * - Safe logging patterns (Section 2.10.2)
 * - Automatic sensitive field redaction (Section 2.10.4)
 */

const express = require('express');
const winston = require('winston');

// ─── Sensitive Field Redaction ────────────────────────────────────────────────
// See Section 2.10.4 and redaction-middleware.js for the full implementation.
// This is a simplified version embedded here for self-contained examples.

const SENSITIVE_FIELDS = [
  'password', 'passwd', 'pwd',
  'token', 'accessToken', 'refreshToken', 'idToken',
  'apiKey', 'api_key',
  'secret', 'clientSecret',
  'ssn', 'socialSecurity',
  'creditCard', 'cardNumber', 'cvv', 'ccv',
  'authorization',
  'cookie',
  'sessionId', 'session_id',
];

function redact(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(redact);

  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => {
      const isSensitive = SENSITIVE_FIELDS.some(
        (field) => key.toLowerCase().includes(field.toLowerCase())
      );
      if (isSensitive) return [key, '[REDACTED]'];
      if (typeof value === 'object') return [key, redact(value)];
      return [key, value];
    })
  );
}

// ─── Winston Logger Setup ─────────────────────────────────────────────────────

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',

  // Always log as structured JSON (Section 2.10.3)
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ssZ' }),
    winston.format.errors({ stack: true }),

    // Redact sensitive fields before writing (Section 2.10.4)
    winston.format((info) => {
      return redact(info);
    })(),

    winston.format.json()
  ),

  defaultMeta: {
    service: process.env.SERVICE_NAME || 'my-app',
    environment: process.env.NODE_ENV || 'development',
  },

  transports: [
    // Console transport — always active
    new winston.transports.Console(),

    // File transport — security events only, retained 1 year (Section 2.10.1)
    new winston.transports.File({
      filename: 'logs/security.log',
      level: 'info',
    }),

    // File transport — errors only, retained 30 days (Section 2.10.1)
    new winston.transports.File({
      filename: 'logs/errors.log',
      level: 'error',
    }),
  ],
});

// ─── Security Event Helpers ───────────────────────────────────────────────────
// Wrapper functions for each of the five critical event types (Section 2.10.1).
// Using named event strings makes logs queryable:
//   e.g. filter by event = "auth.login.failure"

const security = {

  /**
   * Event Type 1: Login attempt (success or failure)
   * Log: userId, timestamp, IP, success/failure
   * Do NOT log: password, session token
   */
  loginSuccess(userId, ip, userAgent) {
    logger.info({
      event: 'auth.login.success',
      userId,
      ip,
      userAgent,
    });
  },

  loginFailure(username, ip, userAgent, reason) {
    logger.warn({
      event: 'auth.login.failure',
      // Log the attempted username (not password) so you can detect
      // credential stuffing against specific accounts.
      username,
      ip,
      userAgent,
      reason, // e.g. 'invalid_password', 'account_locked', 'user_not_found'
    });
  },

  /**
   * Event Type 2: Authorization failure
   * Log: userId, resource, action, result
   */
  authorizationFailure(userId, resource, action, ip) {
    logger.warn({
      event: 'authz.failure',
      userId,
      resource, // e.g. '/admin/users'
      action,   // e.g. 'DELETE'
      ip,
    });
  },

  /**
   * Event Type 3: Privilege change
   * Log: actorId (who made the change), targetUserId, old role, new role
   */
  privilegeChange(actorId, targetUserId, oldRole, newRole, ip) {
    logger.info({
      event: 'authz.privilege.change',
      actorId,
      targetUserId,
      oldRole,
      newRole,
      ip,
    });
  },

  /**
   * Event Type 4: Password reset
   * Log: userId, IP, stage (initiated or completed)
   * Do NOT log: reset token
   */
  passwordResetInitiated(userId, ip) {
    logger.info({
      event: 'auth.password_reset.initiated',
      userId,
      ip,
    });
  },

  passwordResetCompleted(userId, ip) {
    logger.info({
      event: 'auth.password_reset.completed',
      userId,
      ip,
    });
  },

  /**
   * Event Type 5: API key lifecycle
   * Log: userId, keyId (not the key value itself), action
   * Do NOT log: the actual API key value
   */
  apiKeyCreated(userId, keyId, ip) {
    logger.info({
      event: 'apikey.created',
      userId,
      keyId,   // Log the ID/reference, never the key value
      ip,
    });
  },

  apiKeyRevoked(userId, keyId, ip) {
    logger.info({
      event: 'apikey.revoked',
      userId,
      keyId,
      ip,
    });
  },

  /**
   * Generic security event — for anything that doesn't fit the above.
   * Triggers Alert 3 (Section 2.10.6): any SECURITY_EVENT level log.
   */
  securityEvent(type, details, ip) {
    logger.warn({
      event: 'security.event',
      type,
      details,
      ip,
    });
  },
};

// ─── Request Logging Middleware ───────────────────────────────────────────────
// Logs API calls: endpoint, method, status code, duration (Section 2.10.1)
// Does NOT log request body (Section 2.10.2)

function requestLogger(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    logger.info({
      event: 'http.request',
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs: Date.now() - start,
      ip: req.ip,
      // Safe to log: method, path, status, duration, IP
      // NOT logged: req.body, req.headers.authorization, cookies
    });
  });

  next();
}

// ─── Example Express App ──────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(requestLogger);

// Example: Login endpoint demonstrating safe logging
app.post('/login', (req, res) => {
  const { username } = req.body;
  // password is in req.body.password — we deliberately do NOT log it

  // Simulate authentication result
  const success = username === 'alice';

  if (success) {
    security.loginSuccess('usr_abc123', req.ip, req.headers['user-agent']);
    res.json({ message: 'Login successful' });
  } else {
    security.loginFailure(username, req.ip, req.headers['user-agent'], 'invalid_password');
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Example: Admin endpoint demonstrating authorization failure logging
app.delete('/admin/users/:id', (req, res) => {
  const userRole = req.headers['x-user-role'];

  if (userRole !== 'admin') {
    security.authorizationFailure(
      req.headers['x-user-id'] || 'anonymous',
      `/admin/users/${req.params.id}`,
      'DELETE',
      req.ip
    );
    return res.status(403).json({ message: 'Forbidden' });
  }

  res.json({ message: 'User deleted' });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info({
    event: 'server.start',
    port: PORT,
    message: 'Server started',
  });
});

module.exports = { logger, security, requestLogger };
