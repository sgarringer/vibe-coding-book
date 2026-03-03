/**
 * AWS CloudWatch Logging — Node.js Integration
 * Chapter 2.10.5
 *
 * Ships structured security logs to the CloudWatch log groups
 * created by setup.sh.
 *
 * Uses Winston with winston-cloudwatch transport.
 *
 * Install:
 *   npm install winston winston-cloudwatch @aws-sdk/client-cloudwatch-logs
 */

const winston         = require('winston');
const WinstonCloudWatch = require('winston-cloudwatch');

const { redact, winstonRedactFormat } = require('../redaction-middleware');

// ─── Configuration ────────────────────────────────────────────────────────────

const APP_NAME   = process.env.SERVICE_NAME  || 'my-app';
const ENV        = process.env.NODE_ENV      || 'production';
const AWS_REGION = process.env.AWS_REGION    || 'us-east-1';

// Log group names must match what setup.sh created
const LOG_GROUPS = {
  security: `/app/${APP_NAME}/${ENV}/security`,
  app:      `/app/${APP_NAME}/${ENV}/application`,
  audit:    `/app/${APP_NAME}/${ENV}/audit`,
};

// Log stream name — one stream per instance/container
const LOG_STREAM = `${new Date().toISOString().split('T')[0]}/${
  process.env.HOSTNAME || process.env.POD_NAME || 'instance-1'
}`;

// ─── Shared Format ────────────────────────────────────────────────────────────

const sharedFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ssZ' }),
  winston.format.errors({ stack: true }),
  winstonRedactFormat(),   // Redact sensitive fields (Section 2.10.4)
  winston.format.json(),
);

// ─── CloudWatch Transport Factory ────────────────────────────────────────────

function makeCloudWatchTransport(logGroupName, level = 'info') {
  return new WinstonCloudWatch({
    logGroupName,
    logStreamName: LOG_STREAM,
    awsRegion: AWS_REGION,
    level,
    jsonMessage: true,
    // Batch log events to reduce API calls
    uploadRate: 2000,       // flush every 2 seconds
    retentionInDays: false, // retention managed by setup.sh
    handleExceptions: false,
  });
}

// ─── Security Logger ──────────────────────────────────────────────────────────
// Ships to the security log group — 1 year retention

const securityLogger = winston.createLogger({
  level: 'info',
  format: sharedFormat,
  defaultMeta: {
    service: APP_NAME,
    environment: ENV,
  },
  transports: [
    new winston.transports.Console({ silent: ENV === 'production' }),
    makeCloudWatchTransport(LOG_GROUPS.security, 'info'),
  ],
});

// ─── Application Logger ───────────────────────────────────────────────────────
// Ships to the app log group — 30 day retention

const appLogger = winston.createLogger({
  level: 'info',
  format: sharedFormat,
  defaultMeta: {
    service: APP_NAME,
    environment: ENV,
  },
  transports: [
    new winston.transports.Console(),
    makeCloudWatchTransport(LOG_GROUPS.app, 'info'),
  ],
});

// ─── Audit Logger ─────────────────────────────────────────────────────────────
// Ships to the audit log group — 1 year retention

const auditLogger = winston.createLogger({
  level: 'info',
  format: sharedFormat,
  defaultMeta: {
    service: APP_NAME,
    environment: ENV,
  },
  transports: [
    new winston.transports.Console({ silent: ENV === 'production' }),
    makeCloudWatchTransport(LOG_GROUPS.audit, 'info'),
  ],
});

// ─── Security Event Helpers ───────────────────────────────────────────────────
// Routes each event type to the correct log group (Table 2.19)

const security = {

  // Event Type 1: Authentication → security log group
  loginSuccess(userId, ip, userAgent) {
    securityLogger.info({
      event: 'auth.login.success',
      userId, ip, userAgent,
    });
  },

  loginFailure(username, ip, userAgent, reason) {
    securityLogger.warn({
      event: 'auth.login.failure',
      username, ip, userAgent, reason,
    });
  },

  // Event Type 2: Authorization failure → security log group
  authorizationFailure(userId, resource, action, ip) {
    securityLogger.warn({
      event: 'authz.failure',
      userId, resource, action, ip,
    });
  },

  // Event Type 3: Privilege change → audit log group (high sensitivity)
  privilegeChange(actorId, targetUserId, oldRole, newRole, ip) {
    auditLogger.info({
      event: 'authz.privilege.change',
      actorId, targetUserId, oldRole, newRole, ip,
    });
  },

  // Event Type 4: Password reset → security log group
  passwordResetInitiated(userId, ip) {
    securityLogger.info({ event: 'auth.password_reset.initiated', userId, ip });
  },

  passwordResetCompleted(userId, ip) {
    securityLogger.info({ event: 'auth.password_reset.completed', userId, ip });
  },

  // Event Type 5: API key lifecycle → audit log group (high sensitivity)
  apiKeyCreated(userId, keyId, ip) {
    auditLogger.info({ event: 'apikey.created', userId, keyId, ip });
  },

  apiKeyRevoked(userId, keyId, ip) {
    auditLogger.info({ event: 'apikey.revoked', userId, keyId, ip });
  },

  // Generic security event → security log group (triggers Alert 3)
  securityEvent(type, details, ip) {
    securityLogger.warn({ event: 'security.event', type, details, ip });
  },
};

// ─── Request Logger ───────────────────────────────────────────────────────────
// API calls → app log group (30 day retention)

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    appLogger.info({
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

// ─── Error Logger ─────────────────────────────────────────────────────────────
// Errors → app log group (30 day retention)

function errorLogger(err, req, res, next) {
  appLogger.error({
    event: 'app.error',
    // Log error type and sanitized message — not full stack in production
    errorType: err.constructor.name,
    message: err.message,
    // Only include stack trace in non-production environments
    ...(ENV !== 'production' && { stack: err.stack }),
    method: req.method,
    path: req.path,
    ip: req.ip,
  });
  next(err);
}

module.exports = {
  securityLogger,
  appLogger,
  auditLogger,
  security,
  requestLogger,
  errorLogger,
};
