/**
 * Datadog Logging — Node.js Integration
 * Chapter 2.10.5
 *
 * Ships structured security logs to Datadog via Winston + datadog-winston.
 *
 * Install:
 *   npm install winston datadog-winston
 *
 * Set environment variables:
 *   DD_API_KEY   — your Datadog API key
 *   DD_SITE      — your Datadog site (default: datadoghq.com)
 */

const winston        = require('winston');
const DatadogWinston = require('datadog-winston');
const { winstonRedactFormat } = require('../redaction-middleware');

const APP_NAME = process.env.SERVICE_NAME || 'my-app';
const ENV      = process.env.NODE_ENV     || 'production';

// ─── Shared Format ────────────────────────────────────────────────────────────

const sharedFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ssZ' }),
  winston.format.errors({ stack: true }),
  winstonRedactFormat(),
  winston.format.json(),
);

// ─── Datadog Transport ────────────────────────────────────────────────────────

const datadogTransport = new DatadogWinston({
  apiKey: process.env.DD_API_KEY,
  hostname: process.env.HOSTNAME || 'app-server',
  service: APP_NAME,
  ddsource: 'nodejs',
  ddtags: `env:${ENV},service:${APP_NAME}`,
  site: process.env.DD_SITE || 'datadoghq.com',
  // Datadog's log intake accepts up to 5MB per batch
  intakeRegion: process.env.DD_SITE?.includes('eu') ? 'eu' : 'us',
});

// ─── Logger ───────────────────────────────────────────────────────────────────

const logger = winston.createLogger({
  level: 'info',
  format: sharedFormat,
  defaultMeta: {
    service: APP_NAME,
    environment: ENV,
  },
  transports: [
    new winston.transports.Console(),
    datadogTransport,
  ],
});

// ─── Security Event Helpers ───────────────────────────────────────────────────

const security = {

  loginSuccess: (userId, ip, userAgent) =>
    logger.info({ event: 'auth.login.success', userId, ip, userAgent }),

  loginFailure: (username, ip, userAgent, reason) =>
    logger.warn({ event: 'auth.login.failure', username, ip, userAgent, reason }),

  authorizationFailure: (userId, resource, action, ip) =>
    logger.warn({ event: 'authz.failure', userId, resource, action, ip }),

  privilegeChange: (actorId, targetUserId, oldRole, newRole, ip) =>
    logger.info({ event: 'authz.privilege.change', actorId, targetUserId, oldRole, newRole, ip }),

  passwordResetInitiated: (userId, ip) =>
    logger.info({ event: 'auth.password_reset.initiated', userId, ip }),

  passwordResetCompleted: (userId, ip) =>
    logger.info({ event: 'auth.password_reset.completed', userId, ip }),

  apiKeyCreated: (userId, keyId, ip) =>
    logger.info({ event: 'apikey.created', userId, keyId, ip }),

  apiKeyRevoked: (userId, keyId, ip) =>
    logger.info({ event: 'apikey.revoked', userId, keyId, ip }),

  securityEvent: (type, details, ip) =>
    logger.warn({ event: 'security.event', type, details, ip }),
};

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
    });
  });
  next();
}

module.exports = { logger, security, requestLogger };
