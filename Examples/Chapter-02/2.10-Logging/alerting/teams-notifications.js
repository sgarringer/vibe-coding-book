/**
 * Microsoft Teams Notifications — Security Alerts
 * Chapter 2.10.6
 *
 * Sends formatted security alert cards to a Teams channel
 * via Incoming Webhooks.
 *
 * Setup:
 *   1. In Teams, go to the channel → ... → Connectors
 *   2. Add "Incoming Webhook" → Configure → copy the URL
 *   3. Set TEAMS_WEBHOOK_URL environment variable
 *
 * Environment variables:
 *   TEAMS_WEBHOOK_URL  — Incoming webhook URL from Teams
 *   APP_NAME           — Your application name
 *   NODE_ENV           — Deployment environment
 */

const https = require('https');
const url   = require('url');

const APP_NAME = process.env.APP_NAME || 'my-app';
const ENV      = process.env.NODE_ENV || 'production';

// ─── Colour Coding ────────────────────────────────────────────────────────────
// Teams uses hex colours for card theming

const COLOURS = {
  critical: 'FF0000',
  error:    'FF6600',
  warning:  'FFB300',
  info:     '36A64F',
  ok:       '36A64F',
};

// ─── Teams Client ─────────────────────────────────────────────────────────────

function sendToTeams(card) {
  const webhookUrl = process.env.TEAMS_WEBHOOK_URL;

  if (!webhookUrl) {
    console.error('[Teams] TEAMS_WEBHOOK_URL not set — notification not sent');
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    const body   = JSON.stringify(card);
    const parsed = url.parse(webhookUrl);

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
          console.log('[Teams] Notification sent');
        } else {
          console.error(`[Teams] Unexpected response ${res.statusCode}: ${data}`);
        }
        resolve();
      });
    });

    req.on('error', (err) => {
      console.error('[Teams] Request failed:', err.message);
      resolve();
    });

    req.write(body);
    req.end();
  });
}

// ─── Adaptive Card Builder ────────────────────────────────────────────────────
// Teams uses Adaptive Cards for rich message formatting

function buildAdaptiveCard({ title, colour, facts, body, actions = [] }) {
  return {
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.4',
          body: [
            {
              type: 'Container',
              style: 'emphasis',
              items: [
                {
                  type: 'TextBlock',
                  text: title,
                  weight: 'Bolder',
                  size: 'Large',
                  color: colour === COLOURS.critical || colour === COLOURS.error
                    ? 'Attention'
                    : colour === COLOURS.warning
                      ? 'Warning'
                      : 'Good',
                },
              ],
            },
            {
              type: 'FactSet',
              facts: facts.map(([title, value]) => ({ title, value })),
            },
            ...(body ? [{
              type: 'TextBlock',
              text: body,
              wrap: true,
            }] : []),
          ],
          actions: actions.map(({ title, url }) => ({
            type: 'Action.OpenUrl',
            title,
            url,
          })),
          msteams: {
            width: 'Full',
          },
        },
      },
    ],
  };
}

// ─── Alert Functions ──────────────────────────────────────────────────────────

/**
 * Alert 1: Brute Force Detection
 */
async function notifyBruteForce({ ip, failureCount, windowMinutes = 15 }) {
  const card = buildAdaptiveCard({
    title: `🚨 Alert 1: Brute Force Detection — ${APP_NAME} (${ENV})`,
    colour: COLOURS.error,
    facts: [
      ['App', `${APP_NAME} (${ENV})`],
      ['Source IP', ip],
      ['Failed Attempts', `${failureCount} in ${windowMinutes} minutes`],
      ['Time', new Date().toISOString()],
    ],
    body: '**Recommended Actions:**\n- Review login attempts in your log platform\n- Consider blocking this IP at your WAF\n- Check if any attempts succeeded',
    actions: [
      { title: '🔍 View Logs', url: 'https://console.aws.amazon.com/cloudwatch' },
    ],
  });

  return sendToTeams(card);
}

/**
 * Alert 2: Authorization Failure Spike
 */
async function notifyAuthorizationSpike({ userId, failureCount, windowMinutes = 5 }) {
  const card = buildAdaptiveCard({
    title: `⚠️ Alert 2: Authorization Failure Spike — ${APP_NAME} (${ENV})`,
    colour: COLOURS.warning,
    facts: [
      ['App', `${APP_NAME} (${ENV})`],
      ['User ID', userId],
      ['Failures', `${failureCount} in ${windowMinutes} minutes`],
      ['Time', new Date().toISOString()],
    ],
    body: '**Recommended Actions:**\n- Review what resources the user attempted to access\n- Check if the user\'s role changed recently\n- Consider temporarily suspending the account',
  });

  return sendToTeams(card);
}

/**
 * Alert 3: Security Event
 */
async function notifySecurityEvent({ type, details, ip }) {
  const card = buildAdaptiveCard({
    title: `🔴 Alert 3: Security Event — ${APP_NAME} (${ENV})`,
    colour: COLOURS.critical,
    facts: [
      ['App', `${APP_NAME} (${ENV})`],
      ['Event Type', type],
      ['Source IP', ip || 'unknown'],
      ['Time', new Date().toISOString()],
    ],
    body: `**Details:**\n\`\`\`\n${JSON.stringify(details, null, 2)}\n\`\`\`\n\n**This alert requires immediate review.**`,
  });

  return sendToTeams(card);
}

/**
 * Generic alarm notification
 */
async function notifyAlarm({ alarmName, state, description, threshold }) {
  const isOk   = state === 'OK';
  const colour = isOk ? COLOURS.ok : COLOURS.error;
  const icon   = isOk ? '✅' : '🚨';

  const card = buildAdaptiveCard({
    title: `${icon} ${isOk ? 'RESOLVED' : 'ALARM'}: ${alarmName}`,
    colour,
    facts: [
      ['App', `${APP_NAME} (${ENV})`],
      ['State', isOk ? 'RESOLVED' : 'ALARM'],
      ['Threshold', threshold ?? 'N/A'],
      ['Time', new Date().toISOString()],
    ],
    body: description || '',
  });

  return sendToTeams(card);
}

// ─── AWS SNS Lambda Handler ───────────────────────────────────────────────────

async function lambdaHandler(event) {
  for (const record of event.Records) {
    try {
      const snsMessage = JSON.parse(record.Sns.Message);
      await notifyAlarm({
        alarmName:   snsMessage.AlarmName || 'Unknown Alarm',
        state:       snsMessage.NewStateValue,
        description: snsMessage.AlarmDescription || '',
        threshold:   snsMessage.Trigger?.Threshold,
      });
    } catch (err) {
      console.error('[Teams] Failed to process SNS record:', err.message);
    }
  }
}

module.exports = {
  sendToTeams,
  notifyBruteForce,
  notifyAuthorizationSpike,
  notifySecurityEvent,
  notifyAlarm,
  lambdaHandler,
};
