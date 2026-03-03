/**
 * Cloudflare Worker — Security Headers
 *
 * Deploy via Cloudflare Dashboard or Wrangler CLI:
 *   wrangler deploy
 *
 * This worker intercepts all responses and adds security headers.
 */

// Baseline CSP — tune for your application.
// See chapter-02/headers/csp/ for full CSP examples.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: https:",
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "frame-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

const SECURITY_HEADERS = {
  // Strict-Transport-Security
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',

  // X-Frame-Options
  'X-Frame-Options': 'DENY',

  // X-Content-Type-Options
  'X-Content-Type-Options': 'nosniff',

  // Referrer-Policy
  'Referrer-Policy': 'strict-origin-when-cross-origin',

  // Permissions-Policy
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',

  // Content-Security-Policy
  'Content-Security-Policy': CSP,
};

const HEADERS_TO_REMOVE = [
  'X-Powered-By',
  'Server',
];

export default {
  async fetch(request, env, ctx) {
    // Pass the request to the origin
    const response = await fetch(request);

    // Clone the response so headers are mutable
    const newResponse = new Response(response.body, response);

    // Add security headers
    for (const [header, value] of Object.entries(SECURITY_HEADERS)) {
      newResponse.headers.set(header, value);
    }

    // Remove headers that leak server information
    for (const header of HEADERS_TO_REMOVE) {
      newResponse.headers.delete(header);
    }

    return newResponse;
  },
};
