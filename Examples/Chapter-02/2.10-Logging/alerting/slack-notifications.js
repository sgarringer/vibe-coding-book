/**
 * Slack Notifications — Security Alerts
 * Chapter 2.10.6
 *
 * Sends formatted security alert messages to a Slack channel
 * via Incoming Webhooks.
 *
 * Setup:
 *   1. Go to https://api.slack.com/apps → Create New App
 *   2. Enable Incoming Webhooks
 *   3. Add webhook to your #security-alerts channel
 *   4. Copy the webhook URL to SLACK_WEBHOOK_URL
 *
 * Environment variables:
 *   SLACK_WEBHOOK_URL      — Incoming webhook URL
 *   SLACK_CHANNEL          — Override channel (optional, default set in webhook)
 *   APP_NAME               — Your application name
 *   NODE_ENV               — Deployment environment
 */

const https = require('https');
const url   = require('url');

const APP_NAME = process.env.APP_NAME  || 'my-app';
const ENV      = process.env.NODE_ENV  || 'production';

// ─── Colour Coding ────────────────────────────────────────────────────────────
// Slack attachment colours by severity

const COLOURS = {
  critical: '#FF0000',   // red
  error:    '#FF6600',   // orange
  warning:  '#FFB300',   // amber
  info:     '#36A64F',   // green
  ok:       '#36A64F',   // green — alarm resolved
};

// ─── Slack Client ─────────────────────────────────────────────────────────────

/**
 * Send a message to Slack via Incoming Webhook.
 *
 * @param {object} message - Slack Block Kit message payload
 * @returns {Promise<void>}
 */
function sendToSlack(message) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;

  if (!webhookUrl) {
    console.error('[Slack] SLACK_WEBHOOK_URL not set — notification not sent');
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    const body    = JSON.stringify(message);
    const parsed  = url.parse(webhookUrl);

    const options = {
      hostname: parsed.hostname,
      port: 443,
      path: parsed.path,
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
        if (res.statusCode === 200) {
          console.log('[Slack] Notification sent');
          resolve();
        } else {
          console.error(`[Slack] Unexpected response ${res.statusCode}: ${data}`);
          resolve(); // Don't reject — alerting failures should not crash the app
        }
      });
    });

    req.on('error', (err) => {
      console.error('[Slack] Request failed:', err.message);
      resolve(); // Don't reject
    });

    req.write(body);
    req.end();
  });
}

// ─── Message Builders ─────────────────────────────────────────────────────────

/**
 * Alert 1: Brute Force Detection
 * Section 2.10.6 — 5+ failed logins from same IP in 15 minutes
 */
async function notifyBruteForce({ ip, failureCount, windowMinutes = 15, recentUsernames = [] }) {
  const message = {
    text: `🚨 *Brute Force Attack Detected* — ${APP_NAME} (${ENV})`,
    attachments: [
      {
        color: COLOURS.error,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: '🚨 Alert 1: Brute Force Detection',
            },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*App:*\n${APP_NAME} (${ENV})` },
              { type: 'mrkdwn', text: `*Source IP:*\n\`${ip}\`` },
              { type: 'mrkdwn', text: `*Failed Attempts:*\n${failureCount} in ${windowMinutes} min` },
              { type: 'mrkdwn', text: `*Time:*\n${new Date().toISOString()}` },
            ],
          },
          // Show attempted usernames if available (helps identify targeted accounts)
          ...(recentUsernames.length > 0 ? [{
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Targeted Accounts:*\n${recentUsernames.slice(0, 5).join(', ')}${recentUsernames.length > 5 ? ` (+${recentUsernames.length - 5} more)` : ''}`,
            },
          }] : []),
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: '*Recommended Actions:*\n• Review login attempts in your log platform\n• Consider blocking IP `' + ip + '` at your WAF\n• Check if any attempts succeeded',
            },
          },
          {
            type: 'actions',
            elements: [
              {
                type: 'button',
                text: { type: 'plain_text', text: '🔍 View Logs' },
                url: `https://console.aws.amazon.com/cloudwatch/home#logsV2:logs-insights`,
                style: 'primary',
              },
            ],
          },
        ],
      },
    ],
  };

  return sendToSlack(message);
}

/**
 * Alert 2: Authorization Failure Spike
 * Section 2.10.6 — 10+ authz failures from same user in 5 minutes
 */
async function notifyAuthorizationSpike({ userId, failureCount, windowMinutes = 5, resources = [] }) {
  const message = {
    text: `⚠️ *Authorization Failure Spike* — ${APP_NAME} (${ENV})`,
    attachments: [
      {
        color: COLOURS.warning,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: '⚠️ Alert 2: Authorization Failure Spike',
            },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*App:*\n${APP_NAME} (${ENV})` },
              { type: 'mrkdwn', text: `*User ID:*\n\`${userId}\`` },
              { type: 'mrkdwn', text: `*Failures:*\n${failureCount} in ${windowMinutes} min` },
              { type: 'mrkdwn', text: `*Time:*\n${new Date().toISOString()}` },
            ],
          },
          ...(resources.length > 0 ? [{
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Attempted Resources:*\n${resources.slice(0, 5).map(r => `\`${r}\``).join('\n')}`,
            },
          }] : []),
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: '*Recommended Actions:*\n• Review what resources the user attempted to access\n• Check if the user\'s role changed recently\n• Consider temporarily suspending the account if activity looks malicious',
            },
          },
        ],
      },
    ],
  };

  return sendToSlack(message);
}

/**
 * Alert 3: Security Event
 * Section 2.10.6 — any security.event logged
 */
async function notifySecurityEvent({ type, details, ip }) {
  const message = {
    text: `🔴 *Security Event* — ${APP_NAME} (${ENV})`,
    attachments: [
      {
        color: COLOURS.critical,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: '🔴 Alert 3: Security Event',
            },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*App:*\n${APP_NAME} (${ENV})` },
              { type: 'mrkdwn', text: `*Event Type:*\n\`${type}\`` },
              { type: 'mrkdwn', text: `*Source IP:*\n\`${ip || 'unknown'}\`` },
              { type: 'mrkdwn', text: `*Time:*\n${new Date().toISOString()}` },
            ],
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Details:*\n\`\`\`${JSON.stringify(details, null, 2)}\`\`\``,
            },
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: '*This alert requires immediate review.*',
            },
          },
        ],
      },
    ],
  };

  return sendToSlack(message);
}

/**
 * Generic alarm notification — for CloudWatch/Datadog webhook callbacks
 */
async function notifyAlarm({ alarmName, state, description, threshold, value }) {
  const isOk       = state === 'OK';
  const colour     = isOk ? COLOURS.ok : COLOURS.error;
  const icon       = isOk ? '✅' : '🚨';
  const stateLabel = isOk ? 'RESOLVED' : 'ALARM';

  const message = {
    text: `${icon} *${stateLabel}: ${alarmName}* — ${APP_NAME} (${ENV})`,
    attachments: [
      {
        color: colour,
        blocks: [
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Alarm:*\n${alarmName}` },
              { type: 'mrkdwn', text: `*State:*\n${stateLabel}` },
              { type: 'mrkdwn', text: `*Value:*\n${value ?? 'N/A'}` },
              { type: 'mrkdwn', text: `*Threshold:*\n${threshold ?? 'N/A'}` },
              { type: 'mrkdwn', text: `*App:*\n${APP_NAME} (${ENV})` },
              { type: 'mrkdwn', text: `*Time:*\n${new Date().toISOString()}` },
            ],
          },
          ...(description ? [{
            type: 'section',
            text: { type: 'mrkdwn', text: `*Description:*\n${description}` },
          }] : []),
        ],
      },
    ],
  };

  return sendToSlack(message);
}

// ─── AWS SNS Lambda Handler ───────────────────────────────────────────────────
// Deploy as Lambda subscribed to your SNS security alerts topic.
// CloudWatch alarm fires → SNS → Lambda → Slack

async function lambdaHandler(event) {
  for (const record of event.Records) {
    try {
      const snsMessage = JSON.parse(record.Sns.Message);
      const alarmName  = snsMessage.AlarmName || 'Unknown Alarm';
      const state      = snsMessage.NewStateValue;
      const description = snsMessage.AlarmDescription || '';
      const threshold  = snsMessage.Trigger?.Threshold;

      await notifyAlarm({
        alarmName,
        state,
        description,
        threshold,
        value: snsMessage.Trigger?.MetricName,
      });
    } catch (err) {
      console.error('[Slack] Failed to process SNS record:', err.message);
    }
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  sendToSlack,
  notifyBruteForce,
  notifyAuthorizationSpike,
  notifySecurityEvent,
  notifyAlarm,
  lambdaHandler,
};
