# Security Alerting — Complete Setup

Examples for Chapter 2.10.6 

## The Three Required Alerts (Section 2.10.6)

| Alert                     | Trigger                                   | Action                  |
| ------------------------- | ----------------------------------------- | ----------------------- |
| 1. Brute Force Detection  | 5+ failed logins from same IP / 15 min    | Notify security contact |
| 2. Authorization Failures | 10+ authz failures from same user / 5 min | Notify security contact |
| 3. Security Events        | Any `security.event` logged             | Immediate notification  |

## Files

| File                                                | Purpose                                |
| --------------------------------------------------- | -------------------------------------- |
| [cloudwatch-alarms.sh](./cloudwatch-alarms.sh)         | AWS CloudWatch metric filters + alarms |
| [datadog-monitors.json](./datadog-monitors.json)       | Datadog monitor definitions            |
| [pagerduty-integration.js](./pagerduty-integration.js) | PagerDuty incident creation            |
| [slack-notifications.js](./slack-notifications.js)     | Slack webhook notifications            |
| [teams-notifications.js](./teams-notifications.js)     | Microsoft Teams notifications          |
| [brute-force-detection.js](./brute-force-detection.js) | In-process brute force detection       |


## Quick Start

1. Deploy your logging setup from `../centralized/`
2. Run `cloudwatch-alarms.sh` or import `datadog-monitors.json`
3. Configure your notification destination (Slack, Teams, PagerDuty)
4. Add `brute-force-detection.js` to your application for in-process detection
5. Test by triggering 5 failed logins and confirming you receive an alert