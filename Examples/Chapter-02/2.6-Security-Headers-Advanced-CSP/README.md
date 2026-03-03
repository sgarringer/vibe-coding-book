# Content Security Policy — Complete Implementation Examples

Examples for Chapter 2.6.3 

## What These Examples Cover

- Baseline enforcing CSP policy
- Report-Only mode (Section 2.6.3.1)
- Nonce generation middleware (Section 2.6.3.2)
- Violation reporting endpoint

## CSP Rollout Process (Section 2.6.3.1)

1. **Week 1–2** — Deploy with `Content-Security-Policy-Report-Only`
2. **Week 3** — Review violation reports, tune policy
3. **Week 4** — Switch to `Content-Security-Policy` (enforcing)

## Platform Examples

- [Node.js/Express](./nodejs-express/)
- [Python/Flask](./python-flask/)
- [Nginx](./nginx/)
- [Apache](./apache/)
