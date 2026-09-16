// PhishGuard Web Risk backend - the ONE endpoint this backend exposes for
// the extension (plus /health, wired in server.js). Deliberately NOT a
// generic proxy: it accepts exactly one field (`url`), does exactly one
// thing with it (a Web Risk Lookup API check), and returns exactly one of
// three normalized shapes - MATCH / NO_MATCH / UNAVAILABLE.

const express = require("express");
const { checkUrl, WebRiskUnavailableError } = require("../services/webRiskService");

const router = express.Router();

const MAX_URL_LENGTH = 2048;

function isAcceptableUrl(candidate) {
  if (typeof candidate !== "string" || candidate.length === 0 || candidate.length > MAX_URL_LENGTH) {
    return false;
  }
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch (e) {
    return false;
  }
  return parsed.protocol === "http:" || parsed.protocol === "https:";
}

function nowIso() {
  return new Date().toISOString();
}

function unavailableBody(error) {
  return {
    success: false,
    provider: "Google Web Risk",
    matched: false,
    threatTypes: [],
    expireTime: null,
    checkedAt: nowIso(),
    error,
  };
}

router.post("/check", async (req, res) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    return res.status(400).json(unavailableBody("Request body must be a JSON object"));
  }

  const { url } = body;
  if (!isAcceptableUrl(url)) {
    // Spec section 9: reject malformed input safely - this is a client
    // error (bad request), not a Web Risk lookup failure, but the response
    // shape is kept consistent with every other failure mode so the
    // extension's single "success !== true -> unavailable" check handles it
    // without a special case.
    return res.status(400).json(unavailableBody("A valid http:// or https:// url field is required"));
  }

  try {
    const result = await checkUrl(url);
    return res.status(200).json({
      success: true,
      provider: "Google Web Risk",
      matched: result.matched,
      threatTypes: result.matched ? result.threatTypes : [],
      expireTime: result.matched ? result.expireTime : null,
      checkedAt: nowIso(),
      error: null,
    });
  } catch (e) {
    // Covers: timeout, network failure, non-200 from Google (including an
    // invalid API key or a Google-side 429/5xx), malformed Google response.
    // NEVER interpreted as a match, NEVER interpreted as safe - always
    // UNAVAILABLE (spec section 11/17). The specific reason is logged
    // server-side only (see server.js's error logging) - never returned to
    // the client beyond a generic message, and never includes the API key
    // (it is never present in any error message this service throws).
    const message = e instanceof WebRiskUnavailableError ? e.message : "Web Risk unavailable";
    if (req.app.get("logErrors")) {
      // eslint-disable-next-line no-console
      console.error("[webrisk] lookup failed:", e.message);
    }
    return res.status(200).json(unavailableBody(message));
  }
});

module.exports = router;
