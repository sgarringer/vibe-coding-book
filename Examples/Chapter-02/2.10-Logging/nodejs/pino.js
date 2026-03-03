/**
 * Structured Security Logging — Node.js with Pino
 * Chapter 2.10.3
 *
 * Pino is faster than Winston and outputs JSON natively.
 * Use Pino for high-throughput applications.
 *
 * Demonstrates:
 * - Structured JSON output
 * - Built-in redaction via Pino's redact option (Section 2.10.4)
 * - Security event logging for all five critical event types (Section 2.10.1)
 */

const express = require('express');
const pino    = require('pino');

// ─── Pino Logger Setup ────────────────────────────────────────────────────────

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',

  // Pino's built-in redaction — faster than manual object traversal.
  // List JSON paths to sensitive fields. Pino replaces them with [Redacted].
  // See Section 2.10.4.
  redact: {
    paths: [
      'body.password',
      'body.passwd',
      'body.token',
      'body.apiKey',
      'body.api_key',
      'body.secret',
      'body.creditCard',
      'body.cardNumber',
      'body.cvv',
      'body.ssn',
      'headers.authorization',
      'headers.cookie',
      '*.password',
      '*.token',
      '*.apiKey',
      '*.secret',
      '*.ssn',
      '*.creditCard',
    ],
    censor: '[REDACTED]',
  },

  // Structured base fields added to every log entry
  base: {
    service: process.env.SERVICE_NAME || 'my-app',
    environment: process.env.NODE_ENV || 'development',
  },

  // ISO 8601 timestamps (Section 2.10.3)
  timestamp: pino.stdTimeFunctions.isoTime,
});

// ─── Security Event Helpers ───────────────────────────────────────────────────

const security = {

  // Event Type 1: Authentication
  loginSuccess(userId, ip, userAgent) {
    logger.info({ event: 'auth.login.success', userId, ip, userAgent });
  },

  loginFailure(username, ip, userAgent, reason) {
    logger.warn({ event: 'auth.login.failure', username, ip, userAgent, reason });
  },

  // Event Type 2: Authorization failure
  authorizationFailure(userId, resource, action, ip) {
    logger.warn({ event: 'authz.failure', userId, resource, action, ip });
  },

  // Event Type 3: Privilege change
  privilegeChange(actorId, targetUserId, oldRole, newRole, ip) {
    logger.info({ event: 'authz.privilege.change', actorId, targetUserId, oldRole, newRole, ip });
  },

  // Event Type 4: Password reset
  passwordResetInitiated(userId, ip) {
    logger.info({ event: 'auth.password_reset.initiated', userId, ip });
  },

  passwordResetCompleted(userId, ip) {
    logger.info({ event: 'auth.password_reset.completed', userId, ip });
  },

  // Event Type 5: API key lifecycle
  apiKeyCreated(userId, keyId, ip) {
    logger.info({ event: 'apikey.created', userId, keyId, ip });
  },

  apiKeyRevoked(userId, keyId, ip) {
    logger.info({ event: 'apikey.revoked', userId, keyId, ip });
  },

  // Generic security event
  securityEvent(type, details, ip) {
    logger.warn({ event: 'security.event', type, details, ip });
  },
};

// ─── Request Logging Middleware ───────────────────────────────────────────────

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
      // NOT logged: req.body, req.headers.authorization, cookies
    });
  });

  next();
}

// ─── Example Express App ──────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(requestLogger);

app.post('/login', (req, res) => {
  const { username } = req.body;
  const success = username === 'alice';

  if (success) {
    security.loginSuccess('usr_abc123', req.ip, req.headers['user-agent']);
    res.json({ message: 'Login successful' });
  } else {
    security.loginFailure(username, req.ip, req.headers['user-agent'], 'invalid_password');
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  logger.info({ event: 'server.start', port: PORT });
});

module.exports = { logger, security, requestLogger };
