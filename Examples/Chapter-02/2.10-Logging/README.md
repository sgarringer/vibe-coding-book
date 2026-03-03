# Logging — Complete Implementation Examples

Examples for Chapter 2.10 

## What These Examples Cover

- Structured JSON logging (Section 2.10.3)
- Security event logging for the five critical event types (Section 2.10.1)
- Sensitive data exclusion patterns (Section 2.10.2)
- Redaction middleware (Section 2.10.4)

## The Five Critical Events to Log (Section 2.10.1)

1. Every login attempt (success and failure, with IP)
2. Every authorization failure
3. Every privilege change
4. Every password reset
5. Every API key creation or revocation

## Platform Examples

- [Node.js — Winston](./nodejs/winston.js)
- [Node.js — Pino](./nodejs/pino.js)
- [Python — structlog](./python/structlog_example.py)
- [Python — stdlib logging](./python/stdlib_logging.py)
- [Go — zap](./go/zap_example.go)
- [Go — zerolog](./go/zerolog_example.go)

## Log Retention (Section 2.10.1, Table 2.19)

| Event Type             | Retention |
| ---------------------- | --------- |
| Authentication         | 90 days   |
| Authorization failures | 90 days   |
| Data access            | 1 year    |
| Configuration changes  | 1 year    |
| Security events        | 1 year    |
| Errors                 | 30 days   |
| API calls              | 30 days   |

## Testing Your Logs

After implementing, verify:

- Log output is valid JSON (pipe to `jq` to confirm)
- Sensitive fields are absent (grep for 'password', 'token', 'apiKey')
- All five critical event types are being emitted
- Logs are shipping to your central destination (Section 2.10.5)
