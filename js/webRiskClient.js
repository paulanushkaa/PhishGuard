// PhishGuard v5.5.0 + Web Risk - External Threat Intelligence client.
//
// SCOPE: this file is the ENTIRE Web Risk integration surface. It does two
// independent things, kept deliberately separate:
//
//  1. checkWebRisk(url)        - talks to the PhishGuard BACKEND over HTTPS
//                                 (never to Google directly - the Google API
//                                 key lives only on the backend; see
//                                 backend/README.md). Normalizes the
//                                 backend's response into exactly three
//                                 states: MATCH / NO_MATCH / UNAVAILABLE.
//
//  2. fuseWebRiskIntoRisk(...)  - a PURE function that takes js/riskEngine.js's
//                                 output - completely unmodified, byte-for-
//                                 byte the same file as v5.5.0 - and layers
//                                 the Web Risk verdict on top of it. It never
//                                 re-scores, re-weights, or re-derives
//                                 anything riskEngine.js already decided.
//
// This module deliberately does NOT import from js/riskEngine.js, and
// riskEngine.js does not import from this file either. They are wired
// together only in background.js, one layer above both - this is what keeps
// "Web Risk" from ever being mistaken for an eighth rank of the existing,
// frozen seven-rank local detection pipeline. See background.js's own
// comments for exactly where these two functions are called.
//
// THREE-STATE CONTRACT (must match backend/routes/webRisk.js exactly):
//   { available: true,  matched: true,  threatTypes: [...], expireTime, checkedAt, error: null }   MATCH
//   { available: true,  matched: false, threatTypes: [],    expireTime: null, checkedAt, error: null } NO MATCH
//   { available: false, matched: false, threatTypes: [],    expireTime: null, checkedAt, error: "..." } UNAVAILABLE
// A malformed/unexpected backend response is ALWAYS folded into UNAVAILABLE,
// never interpreted as a match or a no-match (spec section 17) - see the
// validation in checkWebRisk() below.

import { fetchWithTimeout } from "./utils.js";

// ---------------------------------------------------------------------------
// Backend URL configuration
// ---------------------------------------------------------------------------
// This is a placeholder DEV default only. Chrome Web Store review requires
// the extension to work with no local dev environment running, so before
// publishing, set the real production backend URL on the options page
// (popup/options.js writes it to chrome.storage.local under STORAGE_KEY) -
// see backend/README.md "Connecting the published extension to production".
// Read fresh from storage on every call (not cached in a module-level
// variable) so a change made on the options page takes effect immediately,
// with no extension reload required.
export const DEFAULT_BACKEND_URL = "http://localhost:8787";
export const STORAGE_KEY = "phishguard_webrisk_backend_url";

export async function getConfiguredBackendUrl() {
  try {
    const stored = await chrome.storage.local.get(STORAGE_KEY);
    const url = stored && stored[STORAGE_KEY];
    return typeof url === "string" && url.trim() ? url.trim().replace(/\/+$/, "") : DEFAULT_BACKEND_URL;
  } catch (e) {
    // chrome.storage unavailable for some reason - fail back to the default
    // rather than throwing; Web Risk becoming unavailable must never take
    // down the rest of the extension (spec section 45).
    return DEFAULT_BACKEND_URL;
  }
}

// ---------------------------------------------------------------------------
// Result cache
// ---------------------------------------------------------------------------
// Keyed by normalized URL only, NOT by tabId - the same pattern
// js/domainService.js already uses for domainCache/dnsCache (a Web Risk
// match/no-match is a property of the URL, not of which tab asked about it).
// This is explicitly permitted by spec section 15 ("or an equivalent
// architecture consistent with the existing project"). It cannot leak
// between tabs: background.js only ever WRITES a result into a specific
// tab's own record under the same isCurrent(tabId, record) guard already
// used for domain/DNS evidence - this cache only avoids re-querying the
// backend for a URL already checked moments ago (by this tab or another).
//
// Per-entry TTL (not a single fixed TtlCache ttl, since the three states
// need different lifetimes):
//   MATCH:       min(backend's expireTime, MATCH_MAX_TTL_MS) - never used
//                past the point Web Risk itself says the match has expired
//                (spec section 15 "Web Risk cache expiration").
//   NO MATCH:    NO_MATCH_TTL_MS - a no-match is a snapshot in time, not
//                permanent-safety evidence (spec section 16 Case 2), so it
//                is not cached indefinitely.
//   UNAVAILABLE: UNAVAILABLE_TTL_MS - short, so a transient backend/network
//                blip is retried soon rather than "sticking" as unavailable.
const NO_MATCH_TTL_MS = 10 * 60 * 1000; // 10 minutes
const UNAVAILABLE_TTL_MS = 30 * 1000; // 30 seconds
const MATCH_MAX_TTL_MS = 24 * 60 * 60 * 1000; // safety ceiling even if expireTime is far out

const resultCache = new Map(); // normalizedUrl -> { result, expiresAt }
const inFlight = new Map(); // normalizedUrl -> Promise<result> (de-dupes concurrent callers, e.g. two tabs)

function cacheGet(key) {
  const entry = resultCache.get(key);
  if (!entry) return undefined;
  if (Date.now() >= entry.expiresAt) {
    resultCache.delete(key);
    return undefined;
  }
  return entry.result;
}

function cacheSet(key, result, ttlMs) {
  if (ttlMs <= 0) return; // already-expired match - do not cache a stale positive
  resultCache.set(key, { result, expiresAt: Date.now() + ttlMs });
}

/** Strips only the fragment - Web Risk matches by URI, and the fragment is
 * never sent to the server for any purpose (it's client-side-only by
 * definition), so two URLs differing only by #fragment are the same lookup. */
function normalizeUrlForWebRisk(url) {
  try {
    const u = new URL(url);
    u.hash = "";
    return u.toString();
  } catch (e) {
    return url;
  }
}

function unavailableResult(error, checkedAt) {
  return {
    available: false,
    provider: "Google Web Risk",
    matched: false,
    threatTypes: [],
    expireTime: null,
    checkedAt,
    error,
  };
}

/**
 * Checks a URL against the PhishGuard backend's Web Risk endpoint.
 * NEVER throws - every failure path resolves to an UNAVAILABLE result
 * (spec section 8/16 Case 3), so a caller can always safely `await` this.
 */
export async function checkWebRisk(url) {
  const key = normalizeUrlForWebRisk(url);

  const cached = cacheGet(key);
  if (cached) return cached;

  const already = inFlight.get(key);
  if (already) return already;

  const promise = (async () => {
    const checkedAt = new Date().toISOString();
    try {
      const backendUrl = await getConfiguredBackendUrl();
      const res = await fetchWithTimeout(
        `${backendUrl}/api/webrisk/check`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: key }),
        },
        5000 // spec section 41: bounded timeout, never blocks the UI indefinitely
      );

      if (!res.ok) {
        const result = unavailableResult(`Backend returned HTTP ${res.status}`, checkedAt);
        cacheSet(key, result, UNAVAILABLE_TTL_MS);
        return result;
      }

      let body;
      try {
        body = await res.json();
      } catch (e) {
        const result = unavailableResult("Backend returned a non-JSON response", checkedAt);
        cacheSet(key, result, UNAVAILABLE_TTL_MS);
        return result;
      }

      // Defensive validation (spec section 17): a malformed/unexpected shape
      // must NEVER be interpreted as a threat, and must NEVER be silently
      // treated as "safe" either - it is UNAVAILABLE, same as a network error.
      if (!body || typeof body !== "object" || body.success !== true) {
        const result = unavailableResult(
          (body && typeof body.error === "string" && body.error) || "Web Risk unavailable",
          checkedAt
        );
        cacheSet(key, result, UNAVAILABLE_TTL_MS);
        return result;
      }

      const matched = body.matched === true;
      const threatTypes = matched && Array.isArray(body.threatTypes)
        ? body.threatTypes.filter((t) => typeof t === "string")
        : [];

      const result = {
        available: true,
        provider: "Google Web Risk",
        matched,
        threatTypes,
        expireTime: matched && typeof body.expireTime === "string" ? body.expireTime : null,
        checkedAt,
        error: null,
      };

      if (matched) {
        let ttlMs = MATCH_MAX_TTL_MS;
        if (result.expireTime) {
          const expiresAtMs = new Date(result.expireTime).getTime();
          if (!Number.isNaN(expiresAtMs)) {
            ttlMs = Math.min(Math.max(0, expiresAtMs - Date.now()), MATCH_MAX_TTL_MS);
          }
        }
        cacheSet(key, result, ttlMs);
      } else {
        cacheSet(key, result, NO_MATCH_TTL_MS);
      }
      return result;
    } catch (e) {
      const result = unavailableResult(`Web Risk backend unreachable: ${e.message}`, checkedAt);
      cacheSet(key, result, UNAVAILABLE_TTL_MS);
      return result;
    } finally {
      inFlight.delete(key);
    }
  })();

  inFlight.set(key, promise);
  return promise;
}

export const THREAT_TYPE_LABELS = {
  SOCIAL_ENGINEERING: "Social Engineering",
  MALWARE: "Malware",
  UNWANTED_SOFTWARE: "Unwanted Software",
};

export function threatTypeLabel(threatType) {
  return THREAT_TYPE_LABELS[threatType] || null;
}

function buildWebRiskExplanationText(threatTypes) {
  const label = threatTypeLabel(threatTypes && threatTypes[0]);
  // Qualified language per Web Risk's user-warning requirements (spec
  // section 21 / docs.cloud.google.com/web-risk/docs/user-warnings): never
  // "confirmed", always "suspected" / "potentially" / "may be".
  return (
    "Google Web Risk flagged this URL as a suspected unsafe resource" +
    (label ? ` (${label})` : "") +
    " - external threat intelligence, independent of PhishGuard's own analysis."
  );
}

/**
 * Fuses js/riskEngine.js's untouched output with a Web Risk check result.
 * Pure function: same inputs always produce the same output, and neither
 * argument is ever mutated.
 *
 * @param {object} originalRisk - the EXACT, unmodified return value of
 *   js/riskEngine.js's computeRisk(). Never altered by this function.
 * @param {object} webRisk - result shape from checkWebRisk() above (or the
 *   "not yet checked" placeholder background.js seeds into a fresh record -
 *   see emptyRecord() - which has available:false and is handled identically
 *   to a genuine UNAVAILABLE result, i.e. as a no-op passthrough).
 * @returns {object} a new object - never the same reference as originalRisk -
 *   with `webRisk`, `webRiskOverride`, `originalVerdict`, and
 *   `originalRiskScore` always present, so the UI can always distinguish
 *   "PhishGuard's own score" from "the final decision" (spec section 28).
 */
export function fuseWebRiskIntoRisk(originalRisk, webRisk) {
  if (!originalRisk) return originalRisk;

  const safeWebRisk = webRisk || unavailableResult("Not yet checked", null);

  const passthrough = () => ({
    ...originalRisk,
    webRisk: safeWebRisk,
    webRiskOverride: false,
    originalVerdict: originalRisk.verdict,
    originalRiskScore: originalRisk.riskScore,
  });

  // Case 3 (UNAVAILABLE, spec section 16): original PhishGuard result stands,
  // completely unchanged. Case 2 (NO MATCH): same - a no-match is not safety
  // evidence and must never lower, raise, or otherwise touch the verdict
  // PhishGuard's own engine already reached (spec section 16 Case 2, and the
  // ML-high-probability protection in section 18 - that protection is
  // entirely a property of riskEngine.js, which this function never calls
  // into or second-guesses).
  if (!safeWebRisk.available || safeWebRisk.matched !== true) {
    return passthrough();
  }

  // Case 1 (MATCH): strong external evidence. This is the ONLY branch that
  // may change the verdict, and it can only ever move it UP toward
  // HIGH_RISK, never down - there is no code path anywhere in this function
  // that lowers a verdict or score.
  if (originalRisk.verdict === "HIGH_RISK") {
    // Already HIGH_RISK on PhishGuard's own evidence - Web Risk corroborates
    // it (spec test case H); nothing left to escalate.
    return passthrough();
  }

  return {
    ...originalRisk,
    verdict: "HIGH_RISK",
    riskScore: Math.max(originalRisk.riskScore, 60), // spec section 16: "at least 60", never a fabricated 100
    webRisk: safeWebRisk,
    webRiskOverride: true,
    originalVerdict: originalRisk.verdict, // preserved, never overwritten (spec section 28)
    originalRiskScore: originalRisk.riskScore,
    explanation: [
      { level: "critical", text: buildWebRiskExplanationText(safeWebRisk.threatTypes) },
      ...(originalRisk.explanation || []),
    ],
  };
}
