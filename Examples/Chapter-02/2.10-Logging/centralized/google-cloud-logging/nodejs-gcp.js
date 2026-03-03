/**
 * Google Cloud Logging — Node.js Integration
 * Chapter 2.10.5
 *
 * Ships structured security logs to Google Cloud Logging.
 *
 * Install:
 *   npm install @google-cloud/logging winston
 *
 * Authentication:
 *   On GCP (Cloud Run, GKE, GCE): automatic via metadata server
 *   Local development: gcloud auth application-default login
 */

const { Logging }  = require('@google-cloud/logging');
const { redact }   = require('../redaction-middleware');

const APP_NAME  = process.env.SERVICE_NAME || 'my-app';
const ENV       = process.env.NODE_ENV     || 'production';
const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT;

const logging = new Logging({ projectId: PROJECT_ID });

// ─── Log Instances ────────────────────────────────────────────────────────────
// One log per retention tier (Table 2.19)

const securityLog = logging.log(`${APP_NAME}-${ENV}-security`);
const auditLog    = logging.log(`${APP_NAME}-${ENV}-audit`);
const appLog      = logging.log(`${APP_NAME}-${ENV}-application`);

// ─── Write Helper ─────────────────────────────────────────────────────────────

async function writeLog(log, severity, data) {
  const safeData = redact(data);

  const entry = log.entry(
    {
      severity,
      resource: { type: 'global' },
      labels: {
        service: APP_NAME,
        environment: ENV,
      },
    },
    {
      ...safeData,
      timestamp: new Date().toISOString(),
    }
  );

  try {
    await log.write(entry);
  } catch (err) {
    // Never let logging errors crash the application
    console.error('Failed to write log to GCP:', err.message);
  }
}

// ─── Security Event Helpers ───────────────────────────────────────────────────

const security = {

  loginSuccess: (userId, ip, userAgent) =>
    writeLog(securityLog, 'INFO', {
      event: 'auth.login.success', userId, ip, userAgent,
    }),

  loginFailure: (username, ip, userAgent, reason) =>
    writeLog(securityLog, 'WARNING', {
      event: 'auth.login.failure', username, ip, userAgent, reason,
    }),

  authorizationFailure: (userId, resource, action, ip) =>
    writeLog(securityLog, 'WARNING', {
      event: 'authz.failure', userId, resource, action, ip,
    }),

  privilegeChange: (actorId, targetUserId, oldRole, newRole, ip) =>
    writeLog(auditLog, 'NOTICE', {
      event: 'authz.privilege.change', actorId, targetUserId, oldRole, newRole, ip,
    }),

  passwordResetInitiated: (userId, ip) =>
    writeLog(securityLog, 'INFO', {
      event: 'auth.password_reset.initiated', userId, ip,
    }),

  passwordResetCompleted: (userId, ip) =>
    writeLog(securityLog, 'INFO', {
      event: 'auth.password_reset.completed', userId, ip,
    }),

  apiKeyCreated: (userId, keyId, ip) =>
    writeLog(auditLog, 'NOTICE', {
      event: 'apikey.created', userId, keyId, ip,
    }),

  apiKeyRevoked: (userId, keyId, ip) =>
    writeLog(auditLog, 'NOTICE', {
      event: 'apikey.revoked', userId, keyId, ip,
    }),

  securityEvent: (type, details, ip) =>
    writeLog(securityLog, 'WARNING', {
      event: 'security.event', type, details, ip,
    }),
};

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    writeLog(appLog, 'INFO', {
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

module.exports = { security, requestLogger, writeLog };
