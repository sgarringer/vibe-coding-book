const express = require('express');
const helmet  = require('helmet');
const crypto  = require('crypto');

const app = express();

// ─── Nonce Generation Middleware ──────────────────────────────────────────────
// Generates a fresh cryptographic nonce for every request.
// The nonce is attached to res.locals so templates can access it.
// See Section 2.6.3.2.

function generateNonce(req, res, next) {
  // 16 random bytes → base64 string
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
}

app.use(generateNonce);

// ─── Helmet CSP Configuration ─────────────────────────────────────────────────
// contentSecurityPolicy runs after generateNonce, so res.locals.cspNonce
// is available when Helmet builds the header value.

app.use((req, res, next) => {
  helmet.contentSecurityPolicy({
    // Set reportOnly: true during Week 1–2 of rollout (Section 2.6.3.1).
    // Switch to false when the policy is tuned.
    reportOnly: false,

    directives: {
      defaultSrc:  ["'self'"],

      // Allow scripts from self + any tag carrying the per-request nonce.
      // The nonce value changes on every request, so 'unsafe-inline' is
      // never needed.
      scriptSrc:   ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],

      styleSrc:    ["'self'"],
      imgSrc:      ["'self'", "data:", "https:"],
      connectSrc:  ["'self'"],
      fontSrc:     ["'self'"],
      objectSrc:   ["'none'"],
      frameSrc:    ["'none'"],
      baseUri:     ["'self'"],
      formAction:  ["'self'"],

      // Violation reporting endpoint (see /csp-violations route below).
      reportUri:   ["/csp-violations"],
    },
  })(req, res, next);
});

// ─── CSP Violation Reporting Endpoint ────────────────────────────────────────
// Browsers POST a JSON body here when a CSP violation occurs.
// Use this during Report-Only mode to understand what your policy blocks.

app.use('/csp-violations', express.json({ type: 'application/csp-report' }));

app.post('/csp-violations', (req, res) => {
  const report = req.body?.['csp-report'];

  if (report) {
    // In production, send this to your logging/SIEM system.
    console.warn('CSP Violation:', {
      blockedUri:   report['blocked-uri'],
      violatedDir:  report['violated-directive'],
      documentUri:  report['document-uri'],
      originalPolicy: report['original-policy'],
    });
  }

  // Always return 204 — browsers ignore the response body.
  res.status(204).end();
});

// ─── Example Routes ───────────────────────────────────────────────────────────

// Root — demonstrates nonce usage in an inline script
app.get('/', (req, res) => {
  const nonce = res.locals.cspNonce;

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>CSP Nonce Demo</title>
    </head>
    <body>
      <h1>CSP Nonce Demo</h1>

      <!--
        ALLOWED: script tag carries the matching nonce.
        The nonce changes on every page load.
        See Section 2.6.3.2, Option 2.
      -->
      <script nonce="${nonce}">
        document.body.insertAdjacentHTML(
          'beforeend',
          '<p>✅ This inline script ran — it has the correct nonce.</p>'
        );
      </script>

      <!--
        BLOCKED: script tag has no nonce.
        The browser will refuse to execute this.
        See Section 2.6.3.2.
      -->
      <script>
        document.body.insertAdjacentHTML(
          'beforeend',
          '<p>❌ This should be blocked by CSP.</p>'
        );
      </script>

      <p>
        Open DevTools → Console to see the CSP violation for the blocked script.<br>
        Open DevTools → Network → this request → Response Headers to see the
        <code>Content-Security-Policy</code> header with the nonce value.
      </p>
    </body>
    </html>
  `);
});

// Report-only demo — same page but uses the Report-Only header
// Useful for testing policy changes without breaking the page.
app.get('/report-only-demo', (req, res) => {
  const nonce = res.locals.cspNonce;

  // Override CSP to report-only for this route only.
  // In a real rollout you would set reportOnly: true globally (see above).
  res.setHeader(
    'Content-Security-Policy-Report-Only',
    `default-src 'self'; script-src 'self' 'nonce-${nonce}'; report-uri /csp-violations`
  );
  // Remove the enforcing header set by Helmet for this demo route.
  res.removeHeader('Content-Security-Policy');

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>CSP Report-Only Demo</title>
    </head>
    <body>
      <h1>CSP Report-Only Mode</h1>
      <p>
        This page uses <code>Content-Security-Policy-Report-Only</code>.
        Violations are logged to <code>/csp-violations</code> but nothing is blocked.
        See Section 2.6.3.1.
      </p>

      <!-- This would be blocked in enforcing mode, but only reported here -->
      <script>
        document.body.insertAdjacentHTML(
          'beforeend',
          '<p>⚠️ This ran (report-only mode) — check server logs for the violation report.</p>'
        );
      </script>
    </body>
    </html>
  `);
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Routes:`);
  console.log(`  /                  — nonce demo (enforcing CSP)`);
  console.log(`  /report-only-demo  — report-only mode demo`);
  console.log(`  /csp-violations    — violation reporting endpoint (POST)`);
});
