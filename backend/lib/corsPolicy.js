// PhishGuard Web Risk backend - CORS allow-list policy.
// Extracted from server.js so it can be unit-tested directly with no
// Express/CORS-package dependency. Behavior is identical to inline logic -
// this file only exists for testability, not to change what's allowed.

/**
 * @param {string|undefined} origin - the request's Origin header, or
 *   undefined for non-browser callers (curl, server-to-server health
 *   checks) which don't send one.
 * @param {object} opts
 * @param {string[]} opts.configuredOrigins - exact origins from
 *   ALLOWED_ORIGINS, always allowed regardless of environment.
 * @param {string} opts.nodeEnv - "production" or anything else.
 * @param {boolean} [opts.requireOrigin=false] - when true, a missing Origin
 *   header is REJECTED rather than allowed. A real browser/extension caller
 *   always sends an Origin header on a cross-origin request (this cannot be
 *   omitted by fetch() - only a script deliberately crafting a raw HTTP
 *   request can), so setting this true on a specific route closes the
 *   trivial "just don't send an Origin header" bypass for that route,
 *   without touching routes (like /health) that legitimately expect
 *   Origin-less callers such as uptime monitors. See server.js for which
 *   routes set this. This does NOT stop a caller that deliberately sets a
 *   matching Origin header value (trivial to do with curl) - it only closes
 *   the single laziest bypass, not determined spoofing. CORS remains a
 *   browser-enforced convention, not an authentication mechanism.
 * @returns {boolean}
 */
function isAllowedOrigin(origin, { configuredOrigins = [], nodeEnv = "development", requireOrigin = false } = {}) {
  if (!origin) return !requireOrigin;
  if (configuredOrigins.includes(origin)) return true;
  if (nodeEnv !== "production") {
    if (origin.startsWith("chrome-extension://")) return true;
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;
  }
  return false;
}

module.exports = { isAllowedOrigin };
