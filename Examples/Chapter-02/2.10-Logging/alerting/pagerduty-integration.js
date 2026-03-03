/**
 * PagerDuty Integration — Security Alert Escalation
 * Chapter 2.10.6
 *
 * Creates PagerDuty incidents when security alerts fire.
 * Attach this to your SNS topic (via Lambda) or call directly
 * from your application when a critical security event occurs.
 *
 * Install:
 *   npm install axios
 *
 * Environment variables:
 *   PAGERDUTY_ROUTING_KEY  — Integration key from PagerDuty service
 *   APP_NAME               — Your application name
 *   NODE_ENV               — Deployment environment
 */

const https = require('https');

const APP_NAME = process.env.APP_NAME  || 'my-app';
const ENV      = process.env.NODE_ENV  || 'production';

// PagerDuty Events API v2 endpoint
const PD_ENDPOINT = 'events.pagerduty.com';
const PD_PATH     = '/v2/enqueue';

// ─── Severity Mapping ─────────────────────────────────────────────────────────
// Maps our alert types to PagerDuty severity levels

const SEVERITY = {
  'auth.login.failure':       'warning',   // individual failure — warning
  'brute_force':              'error',     // threshold crossed — error
  'authz.failure':            'warning',
  'authz_failure_spike':      'error',     // threshold crossed — error
  'security.event':           'critical',  // always critical
  'authz.privilege.change':   'error',
  'apikey.created':           'info',
  'apikey.revoked':           'warning',
};

// ─── PagerDuty Client ─────────────────────────────────────────────────────────

/**
 * Send an event to PagerDuty Events API v2.
 *
 * @param {object} payload - PagerDuty event payload
 * @returns {Promise<object>} - PagerDuty API response
 */
function sendToPagerDuty(payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);

    const options = {
      hostname: PD_ENDPOINT,
      port: 443,
      path: PD_PATH,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Alert Functions ──────────────────────────────────────────────────────────

/**
 * Create a PagerDuty incident for a security alert.
 *
 * @param {object} options
 * @param {string} options.alertType    - One of the alert types from Section 2.10.6
 * @param {string} options.summary      - Human-readable summary
 * @param {object} options.details      - Additional context (IP, userId, etc.)
 * @param {string} [options.dedupKey]   - Deduplication key (same key = same incident)
 * @param {string} [options.routingKey] - Override default routing key
 */
async function createIncident({
  alertType,
  summary,
  details = {},
  dedupKey,
  routingKey,
}) {
  const key = routingKey || process.env.PAGERDUTY_ROUTING_KEY;

  if (!key) {
    console.error('[PagerDuty] PAGERDUTY_ROUTING_KEY not set — incident not created');
    return null;
  }

  const severity = SEVERITY[alertType] || 'error';

  // Dedup key: same alert type + same source = same incident (no duplicate pages)
  const dedup = dedupKey || `${APP_NAME}-${ENV}-${alertType}-${details.ip || details.userId || 'global'}`;

  const payload = {
    routing_key: key,
    event_action: 'trigger',
    dedup_key: dedup,
    payload: {
      summary,
      severity,
      source: `${APP_NAME} (${ENV})`,
      timestamp: new Date().toISOString(),
      component: 'security',
      group: APP_NAME,
      class: alertType,
      custom_details: {
        ...details,
        app: APP_NAME,
        environment: ENV,
        // Include a direct link to the relevant logs
        logsUrl: buildLogsUrl(alertType, details),
      },
    },
    // Links shown in the PagerDuty incident
    links: [
      {
        href: buildLogsUrl(alertType, details),
        text: 'View logs for this alert',
      },
    ],
  };

  try {
    const response = await sendToPagerDuty(payload);

    if (response.status === 202) {
      console.log(`[PagerDuty] Incident created: ${response.body.dedup_key}`);
      return response.body;
    } else {
      console.error(`[PagerDuty] Unexpected response ${response.status}:`, response.body);
      return null;
    }
  } catch (err) {
    // Never let alerting errors crash the application
    console.error('[PagerDuty] Failed to create incident:', err.message);
    return null;
  }
}

/**
 * Resolve a PagerDuty incident when the alert condition clears.
 *
 * @param {string} dedupKey - The dedup key used when creating the incident
 */
async function resolveIncident(dedupKey) {
  const key = process.env.PAGERDUTY_ROUTING_KEY;
  if (!key) return null;

  const payload = {
    routing_key: key,
    event_action: 'resolve',
    dedup_key: dedupKey,
  };

  try {
    const response = await sendToPagerDuty(payload);
    if (response.status === 202) {
      console.log(`[PagerDuty] Incident resolved: ${dedupKey}`);
    }
    return response;
  } catch (err) {
    console.error('[PagerDuty] Failed to resolve incident:', err.message);
    return null;
  }
}

// ─── Pre-built Alert Creators ─────────────────────────────────────────────────
// One function per alert type from Section 2.10.6

/**
 * Alert 1: Brute force detected
 * Call when 5+ failed logins from the same IP within 15 minutes
 */
async function alertBruteForce({ ip, failureCount, windowMinutes = 15 }) {
  return createIncident({
    alertType: 'brute_force',
    summary: `Brute force attack detected from ${ip} — ${failureCount} failures in ${windowMinutes} min`,
    details: { ip, failureCount, windowMinutes },
    dedupKey: `${APP_NAME}-${ENV}-brute-force-${ip}`,
  });
}

/**
 * Alert 2: Authorization failure spike
 * Call when 10+ authorization failures from the same user within 5 minutes
 */
async function alertAuthorizationSpike({ userId, failureCount, windowMinutes = 5 }) {
  return createIncident({
    alertType: 'authz_failure_spike',
    summary: `Authorization failure spike for user ${userId} — ${failureCount} failures in ${windowMinutes} min`,
    details: { userId, failureCount, windowMinutes },
    dedupKey: `${APP_NAME}-${ENV}-authz-spike-${userId}`,
  });
}

/**
 * Alert 3: Security event
 * Call immediately when any security.event is logged
 */
async function alertSecurityEvent({ type, details, ip }) {
  return createIncident({
    alertType: 'security.event',
    summary: `Security event: ${type} from ${ip || 'unknown'}`,
    details: { type, ...details, ip },
    // No dedup key — every security event gets its own incident
  });
}

// ─── AWS SNS Lambda Handler ───────────────────────────────────────────────────
// Deploy this as a Lambda function subscribed to your SNS security alerts topic.
// When CloudWatch alarms fire → SNS → Lambda → PagerDuty

async function lambdaHandler(event) {
  for (const record of event.Records) {
    try {
      const snsMessage = JSON.parse(record.Sns.Message);
      const alarmName  = snsMessage.AlarmName || '';
      const state      = snsMessage.NewStateValue;

      // Only page on ALARM state, not OK
      if (state !== 'ALARM') {
        console.log(`[PagerDuty] Alarm ${alarmName} is ${state} — no action`);
        continue;
      }

      // Map CloudWatch alarm names to PagerDuty alert types
      if (alarmName.includes('BruteForce')) {
        await alertBruteForce({
          ip: 'see-logs',
          failureCount: snsMessage.Trigger?.Threshold || 5,
        });
      } else if (alarmName.includes('AuthorizationFailure')) {
        await alertAuthorizationSpike({
          userId: 'see-logs',
          failureCount: snsMessage.Trigger?.Threshold || 10,
        });
      } else if (alarmName.includes('SecurityEvent')) {
        await alertSecurityEvent({
          type: 'cloudwatch-alarm',
          details: { alarmName },
          ip: 'see-logs',
        });
      } else {
        // Generic incident for any other alarm
        await createIncident({
          alertType: 'security.event',
          summary: `Security alarm: ${alarmName}`,
          details: { alarmName, state, snsMessage },
        });
      }
    } catch (err) {
      console.error('[PagerDuty] Failed to process SNS record:', err.message);
    }
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildLogsUrl(alertType, details) {
  // Build a CloudWatch Logs Insights URL for the relevant query
  const baseUrl = `https://console.aws.amazon.com/cloudwatch/home#logsV2:logs-insights`;
  const queries = {
    'brute_force':          `fields @timestamp, ip, username | filter event = "auth.login.failure" and ip = "${details.ip || ''}" | sort @timestamp desc`,
    'authz_failure_spike':  `fields @timestamp, userId, resource, action | filter event = "authz.failure" and userId = "${details.userId || ''}" | sort @timestamp desc`,
    'security.event':       `fields @timestamp, type, details, ip | filter event = "security.event" | sort @timestamp desc`,
  };
  const query = queries[alertType] || `fields @timestamp, event | sort @timestamp desc`;
  return `${baseUrl}?queryDetail=~(${encodeURIComponent(query)})`;
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  createIncident,
  resolveIncident,
  alertBruteForce,
  alertAuthorizationSpike,
  alertSecurityEvent,
  lambdaHandler,
};
