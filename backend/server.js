// PhishGuard Web Risk backend - entry point.
//
// This process's ONLY job: receive a URL from the PhishGuard extension,
// check it against Google Web Risk, return a normalized result. No
// database, no accounts, no scan history (see project rules) - by design,
// nothing here persists anything between requests except the rate limiter's
// in-memory counters.

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const webRiskRouter = require("./routes/webRisk");
const { isAllowedOrigin } = require("./lib/corsPolicy");
const { createWebRiskLimiter, createWebRiskDailyLimiter, createHealthLimiter } = require("./lib/rateLimitPolicy");

const app = express();
// Render (like most PaaS hosts) places this service behind one proxy/load
// balancer hop, which sets X-Forwarded-For. Without this, express-rate-limit
// refuses to trust that header (ERR_ERL_UNEXPECTED_X_FORWARDED_FOR) and
// req.ip would otherwise resolve to the proxy's own IP for every request,
// not the real client - collapsing everyone into one rate-limit bucket.
// `1` means "trust exactly one hop in front of this app", matching Render's
// single-proxy setup; it must not be `true` (which trusts every hop
// unconditionally, letting a client spoof its own X-Forwarded-For).
app.set("trust proxy", 1);

const PORT = process.env.PORT || 8787;
const NODE_ENV = process.env.NODE_ENV || "development";

app.set("logErrors", true); // routes/webRisk.js logs lookup failures server-side only; never in any response body

app.disable("x-powered-by");
app.use(helmet());

// ---------------------------------------------------------------------------
// CORS - deliberately NOT "*", and deliberately NOT one global policy for
// every route. Configure via ALLOWED_ORIGINS (comma-separated, exact origin
// strings, e.g. "chrome-extension://abcdefghijklmnopabcdefghijklmnop") once
// the extension has a published ID (spec section 12/17: "Do not invent the
// extension ID" - read the actual published ID from the Chrome Web Store
// developer dashboard after first upload, then set it here).
// In non-production environments only, any chrome-extension:// origin and
// localhost/127.0.0.1 origin are additionally allowed, purely so local
// development doesn't require guessing your own unpacked-extension ID.
//
// /api/webrisk requires an Origin header (requireOrigin:true) - a real
// browser/extension fetch() always sends one on a cross-origin request, so
// this closes the laziest bypass (a raw script simply omitting the header)
// on the one route that costs Google Web Risk quota. /health stays lenient
// on a missing Origin, since legitimate uptime monitors/load balancers
// often don't send one. Neither of these is authentication - see
// lib/corsPolicy.js's own doc comment and backend/README.md for the honest
// limits of this control (a caller can still set a matching Origin header
// value deliberately; CORS only stops browsers from lying about origin, not
// scripts from choosing what to send).
// ---------------------------------------------------------------------------
const configuredOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

function corsOptionsFor(requireOrigin) {
  return {
    origin(origin, callback) {
      if (isAllowedOrigin(origin, { configuredOrigins, nodeEnv: NODE_ENV, requireOrigin })) return callback(null, true);
      return callback(new Error("Origin not allowed by PhishGuard backend CORS policy"));
    },
    methods: requireOrigin ? ["POST"] : ["GET"],
  };
}

// Request body is a single short URL string - no legitimate reason for it
// to be large (spec section 11: "reasonable request-size limits"; tightened
// from an earlier 10kb - a JSON-escaped 2048-char URL never approaches 4kb).
app.use(express.json({ limit: "4kb" }));

app.get("/health", cors(corsOptionsFor(false)), createHealthLimiter(), (req, res) => {
  // Deliberately the ONLY thing this returns - no version info, no config,
  // no indication of whether GOOGLE_WEB_RISK_API_KEY is set (spec section
  // 34: "Do not expose the Web Risk API key through /health").
  res.status(200).json({ status: "ok" });
});

// Endpoint-specific rate limiting on the one route that costs Google Web
// Risk quota: a tight per-minute cap PLUS a separate daily cap, so a slow,
// sustained abuser who stays under the per-minute threshold is still bounded
// (see lib/rateLimitPolicy.js). A rate-limited caller gets HTTP 429, which
// js/webRiskClient.js's caller already treats as UNAVAILABLE, never as a
// match (spec section 15) - PhishGuard's own result is unaffected either way.
app.use("/api/webrisk", cors(corsOptionsFor(true)), createWebRiskDailyLimiter(), createWebRiskLimiter(), webRiskRouter);

app.use((req, res) => {
  res.status(404).json({ success: false, error: "Not found" });
});

// Central error handler - production responses never include a stack trace
// or the underlying error message verbatim (spec section 11: "no stack
// traces in production responses"); CORS rejections and any other
// unexpected exception land here.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (NODE_ENV !== "production") {
    console.error(err);
  }
  const message = NODE_ENV === "production" ? "Internal server error" : err.message;
  res.status(err.status || 500).json({ success: false, error: message });
});

app.listen(PORT, () => {
  console.log(`PhishGuard Web Risk backend listening on port ${PORT} (${NODE_ENV})`);
});

module.exports = app;
