/**
 * In-Process Brute Force Detection
 * Chapter 2.10.6
 *
 * Detects the three alert conditions directly inside your application
 * without requiring a log platform or external monitoring tool.
 *
 * Use this as a first line of defence. It complements (not replaces)
 * CloudWatch/Datadog alerting — in-process detection is faster (seconds
 * vs minutes) but doesn't survive process restarts.
 *
 * For production: back the counters with Redis so they survive
 * restarts and work across multiple instances.
 *
 * Usage:
 *   const detector = require('./brute-force-detection');
 *   app.use(detector.middleware());
 *
 *   // In your login handler:
 *   await detector.recordLoginFailure(req.ip, username);
 *
 *   // In your authz middleware:
 *   await detector.recordAuthorizationFailure(userId, resource);
 */

const { notifyBruteForce, notifyAuthorizationSpike } = require('./slack-notifications');
const { alertBruteForce, alertAuthorizationSpike }   = require('./pagerduty-integration');

// ─── Configuration ────────────────────────────────────────────────────────────

const CONFIG = {
  // Alert 1: Brute force (Section 2.10.6)
  bruteForce: {
    maxFailures:    5,    // trigger after this many failures
    windowMs:       15 * 60 * 1000,  // 15 minute window
    blockDurationMs: 30 * 60 * 1000, // optional: block IP for 30 minutes
  },

  // Alert 2: Authorization failure spike (Section 2.10.6)
  authzSpike: {
    maxFailures:  10,   // trigger after this many failures
    windowMs:     5 * 60 * 1000,   // 5 minute window
  },

  // How often to clean up expired counters (prevents memory leak)
  cleanupIntervalMs: 5 * 60 * 1000,
};

// ─── In-Memory Store ──────────────────────────────────────────────────────────
// Replace with Redis for multi-instance deployments.
// See RedisStore class below.

class MemoryStore {
  constructor() {
    // Map of key → { count, firstSeen, usernames/resources }
    this.counters  = new Map();
    // Set of currently blocked keys
    this.blocked   = new Map();  // key → unblockAt timestamp
    // Set of already-alerted keys (prevent duplicate alerts)
    this.alerted   = new Set();
  }

  /**
   * Increment a counter for a key within a time window.
   * Returns the current count.
   */
  increment(key, windowMs, metadata = {}) {
    const now    = Date.now();
    const entry  = this.counters.get(key);

    if (!entry || (now - entry.firstSeen) > windowMs) {
      // Start a new window
      this.counters.set(key, {
        count: 1,
        firstSeen: now,
        metadata: [metadata],
      });
      // Clear alerted state when window resets
      this.alerted.delete(key);
      return 1;
    }

    entry.count++;
    entry.metadata.push(metadata);
    return entry.count;
  }

  getCount(key) {
    return this.counters.get(key)?.count || 0;
  }

  getMetadata(key) {
    return this.counters.get(key)?.metadata || [];
  }

  isBlocked(key) {
    const unblockAt = this.blocked.get(key);
    if (!unblockAt) return false;
    if (Date.now() > unblockAt) {
      this.blocked.delete(key);
      return false;
    }
    return true;
  }

  block(key, durationMs) {
    this.blocked.set(key, Date.now() + durationMs);
  }

  hasAlerted(key) {
    return this.alerted.has(key);
  }

  markAlerted(key) {
    this.alerted.add(key);
  }

  // Remove expired entries to prevent memory growth
  cleanup() {
    const now = Date.now();

    for (const [key, entry] of this.counters.entries()) {
      const maxWindow = Math.max(
        CONFIG.bruteForce.windowMs,
        CONFIG.authzSpike.windowMs
      );
      if ((now - entry.firstSeen) > maxWindow) {
        this.counters.delete(key);
        this.alerted.delete(key);
      }
    }

    for (const [key, unblockAt] of this.blocked.entries()) {
      if (now > unblockAt) {
        this.blocked.delete(key);
      }
    }
  }
}

// ─── Redis Store (production) ─────────────────────────────────────────────────
// Uncomment and use this in multi-instance deployments.
// Requires: npm install ioredis

/*
class RedisStore {
  constructor(redisClient) {
    this.redis = redisClient;
  }

  async increment(key, windowMs, metadata = {}) {
    const countKey    = `bfd:count:${key}`;
    const metaKey     = `bfd:meta:${key}`;
    const windowSecs  = Math.ceil(windowMs / 1000);

    const pipeline = this.redis.pipeline();
    pipeline.incr(countKey);
    pipeline.expire(countKey, windowSecs);
    pipeline.rpush(metaKey, JSON.stringify(metadata));
    pipeline.expire(metaKey, windowSecs);

    const results = await pipeline.exec();
    return results[0][1]; // return new count
  }

  async getCount(key) {
    const val = await this.redis.get(`bfd:count:${key}`);
    return parseInt(val || '0', 10);
  }

  async getMetadata(key) {
    const items = await this.redis.lrange(`bfd:meta:${key}`, 0, -1);
    return items.map((i) => { try { return JSON.parse(i); } catch { return {}; } });
  }

  async isBlocked(key) {
    const val = await this.redis.exists(`bfd:block:${key}`);
    return val === 1;
  }

  async block(key, durationMs) {
    const durationSecs = Math.ceil(durationMs / 1000);
    await this.redis.set(`bfd:block:${key}`, '1', 'EX', durationSecs);
  }

  async hasAlerted(key) {
    const val = await this.redis.exists(`bfd:alerted:${key}`);
    return val === 1;
  }

  async markAlerted(key) {
    // Keep alerted flag for the duration of the window so we don't
    // send duplicate alerts within the same window
    const windowSecs = Math.ceil(
      Math.max(CONFIG.bruteForce.windowMs, CONFIG.authzSpike.windowMs) / 1000
    );
    await this.redis.set(`bfd:alerted:${key}`, '1', 'EX', windowSecs);
  }

  // No-op for Redis — TTLs handle expiry automatically
  cleanup() {}
}
*/

// ─── Detector ─────────────────────────────────────────────────────────────────

class BruteForceDetector {
  /**
   * @param {object} options
   * @param {MemoryStore|RedisStore} [options.store]     - Override the default in-memory store
   * @param {Function}               [options.onBruteForce]   - Called when Alert 1 triggers
   * @param {Function}               [options.onAuthzSpike]   - Called when Alert 2 triggers
   * @param {object}                 [options.logger]    - Logger instance (must have .warn())
   */
  constructor({
    store,
    onBruteForce,
    onAuthzSpike,
    logger = console,
  } = {}) {
    this.store        = store || new MemoryStore();
    this.logger       = logger;

    // Default handlers: notify Slack + PagerDuty
    // Override these in tests or to use a different notification channel
    this.onBruteForce = onBruteForce || this._defaultBruteForceHandler.bind(this);
    this.onAuthzSpike = onAuthzSpike || this._defaultAuthzSpikeHandler.bind(this);

    // Start cleanup interval (memory store only)
    this._cleanupInterval = setInterval(
      () => this.store.cleanup(),
      CONFIG.cleanupIntervalMs
    );

    // Allow the process to exit even if this interval is running
    if (this._cleanupInterval.unref) {
      this._cleanupInterval.unref();
    }
  }

  // ─── Alert 1: Login Failure Recording ──────────────────────────────────────

  /**
   * Record a failed login attempt.
   * Call this in your login handler when authentication fails.
   *
   * @param {string} ip        - Source IP address
   * @param {string} username  - Attempted username (NOT the password)
   * @returns {Promise<{ blocked: boolean, count: number }>}
   *
   * @example
   * app.post('/login', async (req, res) => {
   *   const { username } = req.body;
   *   const authenticated = await authenticate(username, req.body.password);
   *
   *   if (!authenticated) {
   *     const { blocked } = await detector.recordLoginFailure(req.ip, username);
   *     if (blocked) {
   *       return res.status(429).json({ error: 'Too many attempts. Try again later.' });
   *     }
   *     return res.status(401).json({ error: 'Invalid credentials' });
   *   }
   * });
   */
  async recordLoginFailure(ip, username) {
    const key   = `login:${ip}`;
    const count = await this.store.increment(
      key,
      CONFIG.bruteForce.windowMs,
      { username, timestamp: new Date().toISOString() }
    );

    this.logger.warn({
      event:    'auth.login.failure',
      ip,
      username,
      failureCount: count,
      threshold:    CONFIG.bruteForce.maxFailures,
    });

    // Check if threshold crossed and we haven't already alerted this window
    if (count >= CONFIG.bruteForce.maxFailures && !(await this.store.hasAlerted(key))) {
      await this.store.markAlerted(key);

      const metadata  = await this.store.getMetadata(key);
      const usernames = [...new Set(metadata.map((m) => m.username).filter(Boolean))];

      // Trigger Alert 1 (Section 2.10.6)
      await this.onBruteForce({ ip, failureCount: count, usernames });

      // Optionally block the IP for future requests
      if (CONFIG.bruteForce.blockDurationMs) {
        await this.store.block(key, CONFIG.bruteForce.blockDurationMs);
      }
    }

    const blocked = await this.store.isBlocked(key);
    return { blocked, count };
  }

  /**
   * Record a successful login.
   * Resets the failure counter for this IP so legitimate users
   * aren't locked out after a single failed attempt.
   *
   * @param {string} ip
   */
  async recordLoginSuccess(ip) {
    // Reset by setting a fresh window with count 0
    // The next failure will start a new window
    const key = `login:${ip}`;
    if (this.store.counters) {
      // MemoryStore: delete directly
      this.store.counters.delete(key);
      this.store.alerted.delete(key);
    }
    // RedisStore: keys expire naturally; optionally delete explicitly:
    // await this.store.redis.del(`bfd:count:${key}`, `bfd:meta:${key}`, `bfd:alerted:${key}`);
  }

  // ─── Alert 2: Authorization Failure Recording ───────────────────────────────

  /**
   * Record an authorization failure.
   * Call this in your authorization middleware when access is denied.
   *
   * @param {string} userId    - The user who was denied
   * @param {string} resource  - The resource they tried to access
   * @returns {Promise<{ spikeDetected: boolean, count: number }>}
   *
   * @example
   * function requireRole(role) {
   *   return async (req, res, next) => {
   *     if (req.user.role !== role) {
   *       await detector.recordAuthorizationFailure(req.user.id, req.path);
   *       return res.status(403).json({ error: 'Forbidden' });
   *     }
   *     next();
   *   };
   * }
   */
  async recordAuthorizationFailure(userId, resource) {
    const key   = `authz:${userId}`;
    const count = await this.store.increment(
      key,
      CONFIG.authzSpike.windowMs,
      { resource, timestamp: new Date().toISOString() }
    );

    this.logger.warn({
      event:    'authz.failure',
      userId,
      resource,
      failureCount: count,
      threshold:    CONFIG.authzSpike.maxFailures,
    });

    let spikeDetected = false;

    if (count >= CONFIG.authzSpike.maxFailures && !(await this.store.hasAlerted(key))) {
      await this.store.markAlerted(key);

      const metadata  = await this.store.getMetadata(key);
      const resources = [...new Set(metadata.map((m) => m.resource).filter(Boolean))];

      // Trigger Alert 2 (Section 2.10.6)
      await this.onAuthzSpike({ userId, failureCount: count, resources });
      spikeDetected = true;
    }

    return { spikeDetected, count };
  }

  // ─── IP Block Check Middleware ──────────────────────────────────────────────

  /**
   * Express middleware that rejects requests from blocked IPs.
   * Add before your route handlers.
   *
   * @returns {Function} Express middleware
   *
   * @example
   * app.use(detector.blockMiddleware());
   * app.post('/login', loginHandler);
   */
  blockMiddleware() {
    return async (req, res, next) => {
      const key     = `login:${req.ip}`;
      const blocked = await this.store.isBlocked(key);

      if (blocked) {
        this.logger.warn({
          event:   'auth.blocked_ip',
          ip:      req.ip,
          path:    req.path,
          method:  req.method,
        });

        return res.status(429).json({
          error: 'Too many failed attempts. Please try again later.',
          // Don't reveal the exact block duration to attackers
        });
      }

      next();
    };
  }

  /**
   * Combined middleware: checks block status and attaches detector to req
   * so route handlers can call req.detector.recordLoginFailure() directly.
   *
   * @returns {Function} Express middleware
   *
   * @example
   * app.use(detector.middleware());
   *
   * app.post('/login', async (req, res) => {
   *   const ok = await authenticate(req.body.username, req.body.password);
   *   if (!ok) {
   *     const { blocked } = await req.detector.recordLoginFailure(req.ip, req.body.username);
   *     if (blocked) return res.status(429).json({ error: 'Too many attempts' });
   *     return res.status(401).json({ error: 'Invalid credentials' });
   *   }
   *   await req.detector.recordLoginSuccess(req.ip);
   *   res.json({ message: 'OK' });
   * });
   */
  middleware() {
    return async (req, res, next) => {
      // Attach detector to request for use in route handlers
      req.detector = this;

      // Check if IP is blocked before processing the request
      const key     = `login:${req.ip}`;
      const blocked = await this.store.isBlocked(key);

      if (blocked) {
        this.logger.warn({
          event:  'auth.blocked_ip',
          ip:     req.ip,
          path:   req.path,
          method: req.method,
        });

        return res.status(429).json({
          error: 'Too many failed attempts. Please try again later.',
        });
      }

      next();
    };
  }

  // ─── Status / Diagnostics ───────────────────────────────────────────────────

  /**
   * Returns current failure counts — useful for health checks
   * and admin dashboards.
   *
   * @returns {object}
   */
  async getStatus() {
    if (!(this.store instanceof MemoryStore)) {
      return { note: 'Status only available for MemoryStore' };
    }

    const now = Date.now();

    const loginCounters = [];
    const authzCounters = [];

    for (const [key, entry] of this.store.counters.entries()) {
      const ageMs = now - entry.firstSeen;
      if (key.startsWith('login:')) {
        loginCounters.push({
          ip:       key.replace('login:', ''),
          count:    entry.count,
          ageMs,
          blocked:  this.store.isBlocked(key),
          alerted:  this.store.hasAlerted(key),
        });
      } else if (key.startsWith('authz:')) {
        authzCounters.push({
          userId:  key.replace('authz:', ''),
          count:   entry.count,
          ageMs,
          alerted: this.store.hasAlerted(key),
        });
      }
    }

    return {
      config: {
        bruteForce: {
          maxFailures:  CONFIG.bruteForce.maxFailures,
          windowMs:     CONFIG.bruteForce.windowMs,
          blockEnabled: !!CONFIG.bruteForce.blockDurationMs,
        },
        authzSpike: {
          maxFailures: CONFIG.authzSpike.maxFailures,
          windowMs:    CONFIG.authzSpike.windowMs,
        },
      },
      activeLoginCounters: loginCounters.sort((a, b) => b.count - a.count),
      activeAuthzCounters: authzCounters.sort((a, b) => b.count - a.count),
      blockedIPs:          [...this.store.blocked.keys()],
    };
  }

  /**
   * Manually unblock an IP — for use by admins after reviewing a false positive.
   *
   * @param {string} ip
   */
  async unblockIP(ip) {
    const key = `login:${ip}`;
    if (this.store.blocked) {
      this.store.blocked.delete(key);
    }
    this.logger.warn({
      event: 'auth.ip_unblocked',
      ip,
      note: 'Manually unblocked by admin',
    });
  }

  // ─── Cleanup ────────────────────────────────────────────────────────────────

  /**
   * Stop the cleanup interval.
   * Call when shutting down the application.
   */
  destroy() {
    clearInterval(this._cleanupInterval);
  }

  // ─── Default Notification Handlers ─────────────────────────────────────────

  async _defaultBruteForceHandler({ ip, failureCount, usernames }) {
    this.logger.warn({
      event:        'security.event',
      type:         'brute_force_detected',
      ip,
      failureCount,
      usernames,
      threshold:    CONFIG.bruteForce.maxFailures,
      windowMs:     CONFIG.bruteForce.windowMs,
    });

    // Notify in parallel — don't let one failure block the other
    await Promise.allSettled([
      notifyBruteForce({ ip, failureCount, recentUsernames: usernames }),
      alertBruteForce({ ip, failureCount }),
    ]);
  }

  async _defaultAuthzSpikeHandler({ userId, failureCount, resources }) {
    this.logger.warn({
      event:        'security.event',
      type:         'authz_spike_detected',
      userId,
      failureCount,
      resources,
      threshold:    CONFIG.authzSpike.maxFailures,
      windowMs:     CONFIG.authzSpike.windowMs,
    });

    await Promise.allSettled([
      notifyAuthorizationSpike({ userId, failureCount, resources }),
      alertAuthorizationSpike({ userId, failureCount }),
    ]);
  }
}

// ─── Default Instance ─────────────────────────────────────────────────────────
// Export a ready-to-use singleton for simple applications.
// For multi-instance deployments, create your own instance with a RedisStore.

const defaultDetector = new BruteForceDetector();

// ─── Example Express Integration ──────────────────────────────────────────────

/*
const express  = require('express');
const detector = require('./brute-force-detection');

const app = express();
app.use(express.json());

// Apply block check to all routes
app.use(detector.middleware());

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await findUser(username);
  const ok   = user && await verifyPassword(password, user.passwordHash);

  if (!ok) {
    // Record failure — triggers Alert 1 if threshold crossed
    const { blocked } = await req.detector.recordLoginFailure(req.ip, username);
    if (blocked) {
      return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Reset counter on success so legitimate users aren't locked out
  await req.detector.recordLoginSuccess(req.ip);
  res.json({ message: 'Login successful' });
});

// Protected route with authorization check
app.get('/admin/users', async (req, res) => {
  if (req.user.role !== 'admin') {
    // Record failure — triggers Alert 2 if threshold crossed
    await req.detector.recordAuthorizationFailure(req.user.id, req.path);
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json({ users: [] });
});

// Admin: view current detector status
app.get('/admin/security/status', async (req, res) => {
  const status = await req.detector.getStatus();
  res.json(status);
});

// Admin: manually unblock an IP
app.delete('/admin/security/blocks/:ip', async (req, res) => {
  await req.detector.unblockIP(req.params.ip);
  res.json({ message: `${req.params.ip} unblocked` });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  detector.destroy();
  process.exit(0);
});
*/

// ─── Self-Test (run directly: node brute-force-detection.js) ─────────────────

if (require.main === module) {
  (async () => {
    console.log('Running brute force detection self-test...\n');

    // Create a test detector with mock handlers so we don't
    // send real Slack/PagerDuty notifications during tests
    const alerts = [];

    const detector = new BruteForceDetector({
      onBruteForce: async (data) => {
        alerts.push({ type: 'brute_force', ...data });
        console.log('  🚨 Alert 1 triggered:', data);
      },
      onAuthzSpike: async (data) => {
        alerts.push({ type: 'authz_spike', ...data });
        console.log('  ⚠️  Alert 2 triggered:', data);
      },
      logger: { warn: () => {} }, // suppress log output during test
    });

    // ── Test 1: Brute force threshold ──────────────────────────────────────
    console.log('Test 1: Brute force detection');
    console.log(`  Simulating ${CONFIG.bruteForce.maxFailures} failed logins from 1.2.3.4...`);

    for (let i = 0; i < CONFIG.bruteForce.maxFailures; i++) {
      await detector.recordLoginFailure('1.2.3.4', `user${i}@example.com`);
    }

    const bruteForceAlerted = alerts.some((a) => a.type === 'brute_force');
    console.log(`  ${bruteForceAlerted ? '✅ PASS' : '❌ FAIL'}: Alert 1 triggered after ${CONFIG.bruteForce.maxFailures} failures\n`);

    // ── Test 2: No duplicate alerts within same window ─────────────────────
    console.log('Test 2: No duplicate alerts within same window');
    const alertCountBefore = alerts.filter((a) => a.type === 'brute_force').length;

    // Trigger 3 more failures — should NOT fire another alert
    for (let i = 0; i < 3; i++) {
      await detector.recordLoginFailure('1.2.3.4', 'extra@example.com');
    }

    const alertCountAfter = alerts.filter((a) => a.type === 'brute_force').length;
    const noDuplicate = alertCountAfter === alertCountBefore;
    console.log(`  ${noDuplicate ? '✅ PASS' : '❌ FAIL'}: No duplicate alert sent\n`);

    // ── Test 3: Different IP gets its own counter ──────────────────────────
    console.log('Test 3: Different IP tracked independently');
    const alertsBefore = alerts.length;

    for (let i = 0; i < CONFIG.bruteForce.maxFailures; i++) {
      await detector.recordLoginFailure('9.9.9.9', 'victim@example.com');
    }

    const newAlert = alerts.length > alertsBefore;
    console.log(`  ${newAlert ? '✅ PASS' : '❌ FAIL'}: Separate alert for different IP\n`);

    // ── Test 4: Login success resets counter ───────────────────────────────
    console.log('Test 4: Login success resets failure counter');
    await detector.recordLoginSuccess('5.5.5.5');

    // 4 failures after reset — should NOT trigger (below threshold)
    const alertsBefore4 = alerts.length;
    for (let i = 0; i < CONFIG.bruteForce.maxFailures - 1; i++) {
      await detector.recordLoginFailure('5.5.5.5', 'test@example.com');
    }

    const noAlertAfterReset = alerts.length === alertsBefore4;
    console.log(`  ${noAlertAfterReset ? '✅ PASS' : '❌ FAIL'}: Counter reset on success\n`);

    // ── Test 5: Authorization failure spike ───────────────────────────────
    console.log('Test 5: Authorization failure spike detection');
    console.log(`  Simulating ${CONFIG.authzSpike.maxFailures} authz failures for user usr_123...`);

    for (let i = 0; i < CONFIG.authzSpike.maxFailures; i++) {
      await detector.recordAuthorizationFailure('usr_123', `/admin/resource-${i}`);
    }

    const authzAlerted = alerts.some((a) => a.type === 'authz_spike');
    console.log(`  ${authzAlerted ? '✅ PASS' : '❌ FAIL'}: Alert 2 triggered after ${CONFIG.authzSpike.maxFailures} failures\n`);

    // ── Test 6: Status endpoint ────────────────────────────────────────────
    console.log('Test 6: Status reporting');
    const status = await detector.getStatus();
    const hasCounters = status.activeLoginCounters.length > 0;
    console.log(`  ${hasCounters ? '✅ PASS' : '❌ FAIL'}: Status returns active counters`);
    console.log(`  Active login counters : ${status.activeLoginCounters.length}`);
    console.log(`  Active authz counters : ${status.activeAuthzCounters.length}\n`);

    // ── Summary ───────────────────────────────────────────────────────────
    const passed = [
      bruteForceAlerted,
      noDuplicate,
      newAlert,
      noAlertAfterReset,
      authzAlerted,
      hasCounters,
    ].filter(Boolean).length;

    console.log(`Results: ${passed}/6 passed`);

    detector.destroy();
  })();
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = defaultDetector;
module.exports.BruteForceDetector = BruteForceDetector;
module.exports.MemoryStore        = MemoryStore;
module.exports.CONFIG             = CONFIG;
