/**
 * Sensitive Data Redaction Middleware
 * Chapter 2.10.4
 *
 * Standalone redaction module referenced in Section 2.10.4.
 * Drop this into any Node.js project to automatically redact
 * sensitive fields before they reach your logger.
 *
 * Usage:
 *   const { redact, createRedactingLogger, expressRedactionMiddleware } = require('./redaction-middleware');
 */

// ─── Sensitive Field Registry ─────────────────────────────────────────────────
// Add any field names your application uses for sensitive data.
// Matching is case-insensitive and checks if the key *contains* the term,
// so 'userPassword', 'password', and 'PASSWORD' all match 'password'.

const SENSITIVE_FIELDS = [
  // Credentials
  'password', 'passwd', 'pwd', 'pass',
  'pin', 'securityQuestion', 'securityAnswer',

  // Tokens and keys
  'token', 'accessToken', 'refreshToken', 'idToken', 'bearerToken',
  'apiKey', 'api_key', 'apikey',
  'secret', 'clientSecret', 'client_secret',
  'privateKey', 'private_key',
  'sessionId', 'session_id', 'sessionToken',

  // Auth headers
  'authorization', 'cookie', 'setCookie',

  // Payment data (Section 2.10.2, Table 2.20)
  'creditCard', 'credit_card', 'cardNumber', 'card_number',
  'cvv', 'ccv', 'cvc',
  'accountNumber', 'account_number',
  'routingNumber', 'routing_number',

  // Government IDs (Section 2.10.2, Table 2.20)
  'ssn', 'socialSecurity', 'social_security',
  'passport', 'passportNumber',
  'driverLicense', 'driver_license',
  'taxId', 'tax_id', 'ein',

  // Health information (Section 2.10.2, Table 2.20)
  'diagnosis', 'prescription', 'insuranceId', 'insurance_id',
  'medicalRecord', 'medical_record',
];

// ─── Core Redaction Function ──────────────────────────────────────────────────

/**
 * Recursively traverses an object and replaces sensitive field values
 * with '[REDACTED]'.
 *
 * @param {*} obj - Any value (object, array, primitive)
 * @param {string[]} [sensitiveFields] - Override the default sensitive fields list
 * @returns {*} - A new object with sensitive values replaced
 *
 * @example
 * redact({ username: 'alice', password: 'hunter2' })
 * // → { username: 'alice', password: '[REDACTED]' }
 *
 * redact({ user: { id: 1, token: 'abc123' } })
 * // → { user: { id: 1, token: '[REDACTED]' } }
 */
function redact(obj, sensitiveFields = SENSITIVE_FIELDS) {
  // Primitives and null pass through unchanged
  if (typeof obj !== 'object' || obj === null) return obj;

  // Arrays: redact each element
  if (Array.isArray(obj)) return obj.map((item) => redact(item, sensitiveFields));

  // Objects: check each key
  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => {
      const isSensitive = sensitiveFields.some((field) =>
        key.toLowerCase().includes(field.toLowerCase())
      );

      if (isSensitive) {
        return [key, '[REDACTED]'];
      }

      if (typeof value === 'object' && value !== null) {
        return [key, redact(value, sensitiveFields)];
      }

      return [key, value];
    })
  );
}

// ─── Winston Integration ──────────────────────────────────────────────────────

/**
 * Winston format that redacts sensitive fields before writing.
 * Add to your Winston format chain.
 *
 * @example
 * const winston = require('winston');
 * const { winstonRedactFormat } = require('./redaction-middleware');
 *
 * const logger = winston.createLogger({
 *   format: winston.format.combine(
 *     winstonRedactFormat(),
 *     winston.format.json()
 *   )
 * });
 */
function winstonRedactFormat(sensitiveFields = SENSITIVE_FIELDS) {
  const { format } = require('winston');
  return format((info) => redact(info, sensitiveFields))();
}

// ─── Pino Integration ─────────────────────────────────────────────────────────

/**
 * Returns a Pino redact configuration object.
 * Pass this to the Pino constructor's redact option.
 *
 * @example
 * const pino = require('pino');
 * const { pinoRedactConfig } = require('./redaction-middleware');
 *
 * const logger = pino({ redact: pinoRedactConfig() });
 *
 * Note: Pino redact uses path-based matching. This generates common paths.
 * For deep/dynamic keys, use winstonRedactFormat or the Express middleware.
 */
function pinoRedactConfig(sensitiveFields = SENSITIVE_FIELDS) {
  // Generate top-level and one-level-deep paths for each sensitive field
  const paths = sensitiveFields.flatMap((field) => [
    field,
    `*.${field}`,
    `body.${field}`,
    `headers.${field}`,
    `query.${field}`,
  ]);

  return {
    paths,
    censor: '[REDACTED]',
  };
}

// ─── Express Middleware ───────────────────────────────────────────────────────

/**
 * Express middleware that attaches a safe logging helper to res.locals.
 * Use res.locals.safeLog(data) instead of logging req.body directly.
 *
 * This prevents the most common mistake: logging the entire request body
 * and accidentally capturing passwords or tokens (Section 2.10.2).
 *
 * @example
 * app.use(expressRedactionMiddleware());
 *
 * app.post('/login', (req, res) => {
 *   // Safe: only logs what you explicitly pass, with sensitive fields redacted
 *   res.locals.safeLog({ body: req.body });
 *   // → { body: { username: 'alice', password: '[REDACTED]' } }
 * });
 */
function expressRedactionMiddleware(sensitiveFields = SENSITIVE_FIELDS) {
  return (req, res, next) => {
    /**
     * Redact an object before logging it.
     * @param {object} data
     * @returns {object} Redacted copy
     */
    res.locals.safeLog = (data) => redact(data, sensitiveFields);

    /**
     * Build a safe summary of the current request for logging.
     * Never includes the request body.
     * See Section 2.10.2.
     */
    res.locals.requestSummary = () => ({
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      // NOT included: req.body, req.headers.authorization, req.headers.cookie
    });

    next();
  };
}

// ─── Audit Log Helper ─────────────────────────────────────────────────────────

/**
 * Wraps a logger instance to automatically redact all log calls.
 * Works with any logger that has .info(), .warn(), .error() methods.
 *
 * @param {object} logger - Your logger instance (Winston, Pino, console, etc.)
 * @param {string[]} [sensitiveFields] - Override the default sensitive fields list
 * @returns {object} - Wrapped logger with automatic redaction
 *
 * @example
 * const winston = require('winston');
 * const { createRedactingLogger } = require('./redaction-middleware');
 *
 * const rawLogger = winston.createLogger({ ... });
 * const logger = createRedactingLogger(rawLogger);
 *
 * // Now all log calls are automatically redacted
 * logger.info('Login attempt', { username: 'alice', password: 'hunter2' });
 * // Logs: { username: 'alice', password: '[REDACTED]' }
 */
function createRedactingLogger(logger, sensitiveFields = SENSITIVE_FIELDS) {
  const wrap = (method) => (...args) => {
    const redactedArgs = args.map((arg) =>
      typeof arg === 'object' ? redact(arg, sensitiveFields) : arg
    );
    return logger[method](...redactedArgs);
  };

  return new Proxy(logger, {
    get(target, prop) {
      if (['info', 'warn', 'error', 'debug', 'fatal', 'trace'].includes(prop)) {
        return wrap(prop);
      }
      return target[prop];
    },
  });
}

// ─── Validation Helper ────────────────────────────────────────────────────────

/**
 * Scans a log entry and returns any sensitive fields found.
 * Use in tests to verify your logging is safe.
 *
 * @param {object} logEntry - A parsed log entry object
 * @returns {string[]} - List of sensitive field names found (should be empty)
 *
 * @example
 * const violations = findSensitiveFields({ username: 'alice', password: 'hunter2' });
 * // → ['password']
 *
 * // In a test:
 * expect(findSensitiveFields(logEntry)).toHaveLength(0);
 */
function findSensitiveFields(logEntry, sensitiveFields = SENSITIVE_FIELDS) {
  const found = [];

  function scan(obj, path = '') {
    if (typeof obj !== 'object' || obj === null) return;
    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;
      const isSensitive = sensitiveFields.some((field) =>
        key.toLowerCase().includes(field.toLowerCase())
      );
      if (isSensitive && value !== '[REDACTED]') {
        found.push(currentPath);
      }
      if (typeof value === 'object') {
        scan(value, currentPath);
      }
    }
  }

  scan(logEntry);
  return found;
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  SENSITIVE_FIELDS,
  redact,
  winstonRedactFormat,
  pinoRedactConfig,
  expressRedactionMiddleware,
  createRedactingLogger,
  findSensitiveFields,
};

// ─── Self-Test (run directly: node redaction-middleware.js) ───────────────────

if (require.main === module) {
  console.log('Running redaction self-test...\n');

  const testCases = [
    {
      label: 'Login body — password should be redacted',
      input: { username: 'alice', password: 'hunter2', ip: '1.2.3.4' },
      expectRedacted: ['password'],
    },
    {
      label: 'Nested token — should be redacted',
      input: { user: { id: 'usr_123', token: 'abc.def.ghi' } },
      expectRedacted: ['user.token'],
    },
    {
      label: 'API key — should be redacted',
      input: { endpoint: '/api/data', apiKey: 'sk-live-abc123' },
      expectRedacted: ['apiKey'],
    },
    {
      label: 'Safe fields — should pass through',
      input: { userId: 'usr_123', ip: '1.2.3.4', event: 'auth.login.success' },
      expectRedacted: [],
    },
  ];

  let passed = 0;
  let failed = 0;

  for (const { label, input, expectRedacted } of testCases) {
    const result = redact(input);
    const violations = findSensitiveFields(result);
    const ok = violations.length === 0;

    if (ok) {
      console.log(`  ✅ PASS: ${label}`);
      console.log(`     Input:  ${JSON.stringify(input)}`);
      console.log(`     Output: ${JSON.stringify(result)}\n`);
      passed++;
    } else {
      console.log(`  ❌ FAIL: ${label}`);
      console.log(`     Unredacted fields: ${violations.join(', ')}\n`);
      failed++;
    }
  }

  console.log(`Results: ${passed} passed, ${failed} failed`);
}
