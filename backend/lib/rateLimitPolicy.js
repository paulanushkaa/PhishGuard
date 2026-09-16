// PhishGuard Web Risk backend - rate limit configuration.
//
// Split out of server.js (same reasoning as lib/corsPolicy.js) so the
// configuration is explicit, reviewable, and testable in isolation. This is
// abuse/quota protection, not authentication - see backend/README.md and
// the Step 4 audit note for the honest limits of what this does and does
// not defend against.

const rateLimit = require("express-rate-limit");

const WEBRISK_MESSAGE = {
  success: false,
  provider: "Google Web Risk",
  matched: false,
  threatTypes: [],
  expireTime: null,
  error: "Rate limit exceeded - try again shortly",
};

const WEBRISK_DAILY_MESSAGE = {
  ...WEBRISK_MESSAGE,
  error: "Daily rate limit exceeded",
};

/** Per-minute cap on the expensive route (the one that calls Google and
 * costs quota). Tighter than the old shared /api/ limit (60/min) - default
 * 30/min is generous for a single real browsing session (PhishGuard checks
 * at most one Web Risk lookup per navigation, cached afterward - see
 * js/webRiskClient.js), while meaningfully slowing down direct abuse. */
function createWebRiskLimiter() {
  return rateLimit({
    windowMs: Number(process.env.WEBRISK_RATE_LIMIT_WINDOW_MS) || 60 * 1000,
    limit: Number(process.env.WEBRISK_RATE_LIMIT_MAX) || 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: WEBRISK_MESSAGE,
  });
}

/** Longer-window cap on the same route, to bound worst-case cost even from
 * an abuser who deliberately stays under the per-minute threshold (a slow,
 * sustained drip). Default 500/day per IP - well above any plausible real
 * single-user browsing volume. */
function createWebRiskDailyLimiter() {
  return rateLimit({
    windowMs: Number(process.env.WEBRISK_DAILY_RATE_LIMIT_WINDOW_MS) || 24 * 60 * 60 * 1000,
    limit: Number(process.env.WEBRISK_DAILY_RATE_LIMIT_MAX) || 500,
    standardHeaders: true,
    legacyHeaders: false,
    message: WEBRISK_DAILY_MESSAGE,
  });
}

/** Independent, generous limit on /health only - this route never calls
 * Google and costs nothing, so this exists purely to stop trivial resource
 * exhaustion / log-noise, and is deliberately loose enough to never
 * interfere with real uptime monitoring (checks every few seconds are
 * still far under this). */
function createHealthLimiter() {
  return rateLimit({
    windowMs: 60 * 1000,
    limit: Number(process.env.HEALTH_RATE_LIMIT_MAX) || 120,
    standardHeaders: true,
    legacyHeaders: false,
  });
}

module.exports = { createWebRiskLimiter, createWebRiskDailyLimiter, createHealthLimiter };
