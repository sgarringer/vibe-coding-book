const express = require('express');
const helmet = require('helmet');

const app = express();

// ─── Option 1: Helmet Defaults (quickest) ────────────────────────────────────
// Helmet's defaults cover most headers with sensible values.
// Uncomment this and remove Option 2 if you want the simplest setup.
//
// app.use(helmet());

// ─── Option 2: Explicit Configuration (recommended) ──────────────────────────
// Explicitly configure each header so the values are visible and intentional.

app.use(
  helmet({
    // Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    strictTransportSecurity: {
      maxAge: 31536000,         // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    },

    // X-Frame-Options: DENY
    frameguard: {
      action: 'deny',
    },

    // X-Content-Type-Options: nosniff
    noSniff: true,

    // Referrer-Policy: strict-origin-when-cross-origin
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin',
    },

    // Permissions-Policy: geolocation=(), microphone=(), camera=()
    // Note: Helmet does not set Permissions-Policy directly.
    // We add it manually in the middleware below.

    // Content-Security-Policy
    // See chapter-02/headers/csp/ for full CSP examples.
    // This is a baseline policy — tune it for your application.
    contentSecurityPolicy: {
      directives: {
        defaultSrc:  ["'self'"],
        scriptSrc:   ["'self'"],
        styleSrc:    ["'self'"],
        imgSrc:      ["'self'", "data:", "https:"],
        connectSrc:  ["'self'"],
        fontSrc:     ["'self'"],
        objectSrc:   ["'none'"],
        frameSrc:    ["'none'"],
        baseUri:     ["'self'"],
        formAction:  ["'self'"],
      },
    },
  })
);

// Permissions-Policy — not yet covered by Helmet, added manually
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=()'
  );
  next();
});

// ─── Example Route ────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head><title>Security Headers Demo</title></head>
      <body>
        <h1>Security Headers Active</h1>
        <p>Open DevTools → Network → click this request → Response Headers
           to verify all headers are present.</p>
      </body>
    </html>
  `);
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Verify headers at https://securityheaders.com');
});
