// PhishGuard Web Risk backend - Google Web Risk Lookup API client.
//
// This is the ONLY file in the whole project (extension + backend) that
// talks to Google, and the ONLY file that ever reads GOOGLE_WEB_RISK_API_KEY.
// Source of truth for the request/response shape used here:
//   https://docs.cloud.google.com/web-risk/docs/lookup-api
//
// Request:  GET https://webrisk.googleapis.com/v1/uris:search
//             ?threatTypes=SOCIAL_ENGINEERING&threatTypes=MALWARE
//             &threatTypes=UNWANTED_SOFTWARE&uri=<url-encoded>&key=<API_KEY>
// Response on a match:    { "threat": { "threatTypes": [...], "expireTime": "..." } }
// Response on no match:   {}   (an empty JSON object - not a 404, not null)
//
// Deliberately does NOT use Safe Browsing API v4 / threatMatches.find, and
// does NOT call any other Google security API - Web Risk Lookup only.

const WEB_RISK_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search";
const THREAT_TYPES = ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"];

class WebRiskUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = "WebRiskUnavailableError";
  }
}

function buildRequestUrl(url, apiKey) {
  const params = new URLSearchParams();
  for (const t of THREAT_TYPES) params.append("threatTypes", t);
  params.append("uri", url);
  params.append("key", apiKey);
  return `${WEB_RISK_ENDPOINT}?${params.toString()}`;
}

/**
 * Looks up a single URL against Google Web Risk.
 *
 * @param {string} url - the exact URL to check (already validated by the
 *   caller - see routes/webRisk.js).
 * @param {object} [opts]
 * @param {Function} [opts.fetchImpl] - injectable for tests; defaults to
 *   global fetch (Node 18+).
 * @param {number} [opts.timeoutMs] - hard timeout; a hang must never be
 *   possible (spec: "backend's Google Web Risk request must have a finite
 *   timeout").
 * @returns {Promise<{matched: boolean, threatTypes: string[], expireTime: string|null}>}
 * @throws {WebRiskUnavailableError} on ANY failure - timeout, network error,
 *   non-200 response, invalid API key, malformed JSON, or an unexpected
 *   response shape. The caller (routes/webRisk.js) is responsible for
 *   turning that into the normalized `success:false` / UNAVAILABLE shape -
 *   this function never itself decides "unavailable means safe" or
 *   "unavailable means threat"; it simply reports failure.
 */
async function checkUrl(url, opts = {}) {
  const { fetchImpl = fetch, timeoutMs = 4000 } = opts;
  const apiKey = process.env.GOOGLE_WEB_RISK_API_KEY;
  if (!apiKey) {
    throw new WebRiskUnavailableError("GOOGLE_WEB_RISK_API_KEY is not configured on the backend");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetchImpl(buildRequestUrl(url, apiKey), { method: "GET", signal: controller.signal });
  } catch (e) {
    if (e.name === "AbortError") {
      throw new WebRiskUnavailableError(`Web Risk request timed out after ${timeoutMs}ms`);
    }
    throw new WebRiskUnavailableError(`Web Risk request failed: ${e.message}`);
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    // Deliberately does not distinguish 4xx/5xx here beyond the message -
    // an invalid API key (typically 400/403), a Google-side 5xx, and a rate
    // limit (429) all collapse to the same UNAVAILABLE outcome one layer up
    // (spec section 11/16 Case 3 - none of these may ever be interpreted as
    // a threat match or as "safe").
    throw new WebRiskUnavailableError(`Web Risk API returned HTTP ${res.status}`);
  }

  let body;
  try {
    body = await res.json();
  } catch (e) {
    throw new WebRiskUnavailableError("Web Risk API returned a non-JSON response");
  }

  // Per the documented contract: {} (no "threat" key at all) means no match.
  // Presence of a non-empty threat.threatTypes array means a match.
  if (!body || typeof body !== "object" || !body.threat || !Array.isArray(body.threat.threatTypes) || body.threat.threatTypes.length === 0) {
    return { matched: false, threatTypes: [], expireTime: null };
  }

  return {
    matched: true,
    threatTypes: body.threat.threatTypes.filter((t) => typeof t === "string"),
    expireTime: typeof body.threat.expireTime === "string" ? body.threat.expireTime : null,
  };
}

module.exports = { checkUrl, WebRiskUnavailableError, THREAT_TYPES, buildRequestUrl };
