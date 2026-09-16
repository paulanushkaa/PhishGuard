// PhishGuard v5.0 - background service worker.
//
// Owns the full detection pipeline per tab: URL feature extraction + ML,
// DOM evidence merged in from content.js, optional domain/DNS lookups, and
// risk fusion via riskEngine.js. The popup only ever *reads* this state -
// it never runs detection itself, so closing the popup never interrupts
// protection.
//
// NAVIGATION SAFETY (spec section 21-22): every analysis record carries a
// monotonically increasing `generation` counter per tab, in addition to the
// exact normalized URL. Any asynchronous result (domain/DNS
// lookups, or a DOM-analysis message from content.js) is checked against
// BOTH the current URL AND the current generation before being applied -
// this is stronger than a URL-string check alone, since it also handles a
// tab re-navigating to the exact same URL twice in quick succession (the
// second navigation's evidence must never be overwritten by a late-arriving
// result from the first). A stale result is silently dropped, never applied.
//
// REDIRECT SAFETY: the fast local path (URL + ML only) is, by construction,
// incapable of producing a HIGH_RISK verdict on its own - see
// js/riskEngine.js's fixed weight caps (ml + urlHeuristics max = 50 points,
// below the 60-point HIGH_RISK floor). This means the warning interstitial
// can never fire during the "incomplete initial analysis" phase before DOM
// evidence has arrived; it can only fire once genuinely corroborating
// evidence (DOM, domain age, etc.) is present and the risk
// engine's explicit corroboration policy is satisfied.

import { predictUrl } from "./js/mlModel.js";
import { urlFacts, extractFeatures } from "./js/featureExtractor.js";
import { ensurePslLoaded } from "./js/psl.js";
import { computeRisk } from "./js/riskEngine.js";
import { getDomainIntelligence, getDnsRecords } from "./js/domainService.js";
import { resetChain, recordRedirect, recordCommitted, clearChain, summarizeChain } from "./js/redirectTracker.js";
// EXTERNAL THREAT-INTELLIGENCE VALIDATION LAYER (not one of Ranks 1-7 - see
// js/webRiskClient.js's own header comment). js/riskEngine.js above is
// completely untouched by this integration; checkWebRisk()/fuseWebRiskIntoRisk()
// are the only two functions this file calls to add Google Web Risk as an
// independent validation source on top of riskEngine.js's existing verdict.
import { checkWebRisk, fuseWebRiskIntoRisk } from "./js/webRiskClient.js";

// Warm the PSL cache at service-worker startup so the very first navigation
// doesn't pay the fetch cost inline.
ensurePslLoaded().catch(() => {
  /* if this fails, featureExtractor/psl calls will surface it per-request */
});

const tabAnalysis = new Map(); // tabId -> analysis record
const tabGeneration = new Map(); // tabId -> current generation number
const allowedOnce = new Set(); // "tabId|url" pairs the user chose to proceed past

const NON_ANALYZABLE_SCHEMES = ["chrome:", "chrome-extension:", "edge:", "about:", "devtools:", "view-source:", "file:"];

function isAnalyzable(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    return !NON_ANALYZABLE_SCHEMES.includes(u.protocol);
  } catch (e) {
    return false;
  }
}

function nextGeneration(tabId) {
  const g = (tabGeneration.get(tabId) || 0) + 1;
  tabGeneration.set(tabId, g);
  return g;
}

function emptyRecord(url, generation) {
  return {
    url,
    generation,
    ml: { available: false, reason: "Not yet analyzed" },
    domSignals: { available: false },
    domain: { available: false },
    dns: { available: false },
    redirect: { available: false }, // Rank 1 - filled in synchronously in startUrlAnalysis before first recomputeRisk
    risk: null,
    // EXTERNAL THREAT-INTELLIGENCE VALIDATION LAYER: `webRisk` starts as an
    // explicit "not yet checked" placeholder (pending:true, available:false)
    // rather than null, so fuseWebRiskIntoRisk() can treat "no result yet"
    // identically to "genuinely unavailable" - a safe passthrough in both
    // cases (see js/webRiskClient.js). `finalRisk` is what the popup/badge/
    // warning-redirect actually read; `risk` itself remains exactly what
    // js/riskEngine.js decided, unmodified, for as long as this record exists.
    webRisk: { available: false, pending: true, provider: "Google Web Risk", matched: false, threatTypes: [], expireTime: null, checkedAt: null, error: null },
    finalRisk: null,
    updatedAt: Date.now(),
  };
}

/** Recomputes `record.finalRisk` from the current `record.risk` (PhishGuard's
 * own, untouched verdict) and `record.webRisk` (external validation state).
 * Call this every time either one changes - see every call site below. Pure
 * wiring only; all the actual fusion logic lives in js/webRiskClient.js. */
function applyWebRiskFusion(record) {
  record.finalRisk = record.risk ? fuseWebRiskIntoRisk(record.risk, record.webRisk) : record.risk;
}

/** True only if `record` is still the current, non-stale analysis for this
 * tab (matches both the live URL and generation) - the guard every
 * asynchronous evidence update must pass before mutating shared state. */
function isCurrent(tabId, record) {
  const current = tabAnalysis.get(tabId);
  return !!current && current === record && current.generation === tabGeneration.get(tabId);
}

// RANK 7 (performance): urlFacts()/extractFeatures() are pure functions of
// record.url alone (once the PSL is loaded, both are cheap synchronous
// parsing - no network, no per-call variance). Previously recomputeRisk()
// re-derived both from scratch every single time it ran - and it can run
// up to 4x for one navigation (after ML, after domain, after DNS, after a
// DOM-analysis message) - so a page could pay for the same URL parse,
// entropy calculation, and PSL lookup four times over. Caching them on the
// record, keyed by the exact url string, removes that duplicate work
// entirely while staying provably safe: the moment record.url changes
// (a real re-navigation - see startUrlAnalysis's generation bump), the
// cache key no longer matches and this recomputes for real. This caches
// derived FACTS ONLY, never the risk verdict itself - domSignals/domain/dns
// changes still trigger a full, fresh computeRisk() call every time, so a
// dynamic page (e.g. a form injected after load) remains fully analyzable.
async function getCachedUrlDerivedFacts(record) {
  if (record._factsCache && record._factsCache.url === record.url) {
    return record._factsCache;
  }
  const facts = await urlFacts(record.url);
  let mlFeatures = null;
  try {
    mlFeatures = await extractFeatures(record.url);
  } catch (e) {
    mlFeatures = null;
  }
  const cache = { url: record.url, facts, mlFeatures };
  record._factsCache = cache;
  return cache;
}

async function recomputeRisk(record) {
  const { facts, mlFeatures } = await getCachedUrlDerivedFacts(record);
  record.risk = computeRisk({
    ml: record.ml,
    urlFacts: facts,
    mlFeatures,
    domSignals: record.domSignals,
    domain: record.domain,
    dns: record.dns,
    redirect: record.redirect, // Rank 1 - {available:false} until startUrlAnalysis fills it in
  });
  record.urlFacts = facts;
  record.updatedAt = Date.now();
  return record.risk;
}

async function updateBadge(tabId, risk) {
  try {
    if (!risk) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }
    const colors = { SAFE: "#1a9f4a", SUSPICIOUS: "#e0a800", HIGH_RISK: "#d32f2f" };
    const labels = { SAFE: "", SUSPICIOUS: "!", HIGH_RISK: "!!" };
    await chrome.action.setBadgeBackgroundColor({ tabId, color: colors[risk.verdict] || "#888" });
    await chrome.action.setBadgeText({ tabId, text: labels[risk.verdict] || "" });
  } catch (e) {
    /* tab may have closed */
  }
}

// Popups are short-lived and only ever *read* tabAnalysis via
// PHISHGUARD_GET_ANALYSIS - they don't get pushed updates automatically.
// DOM evidence in particular can legitimately arrive well after the popup's
// first snapshot request (document_idle + settle delay + debounced
// MutationObserver re-scans on heavier/SPA pages), which is what left the
// popup stuck showing "Webpage: Unavailable" even once evidence had, in
// fact, arrived a moment later. This reuses the same chrome.runtime
// message channel already used elsewhere (no polling) so the popup can
// re-fetch and re-render the instant fresh DOM evidence lands, however
// late it arrives. If no popup is open, there's simply no listener to
// receive it - safe to ignore.
function notifyPopupOfDomUpdate(tabId) {
  chrome.runtime.sendMessage({ type: "PHISHGUARD_ANALYSIS_UPDATED", tabId }).catch(() => {
    /* no popup currently open to receive this - nothing to update */
  });
}

async function maybeRedirectToWarning(tabId, record) {
  // finalRisk (PhishGuard's own verdict, optionally escalated by a Web Risk
  // MATCH - see js/webRiskClient.js) is what actually gates the warning
  // interstitial now. Falling back to record.risk covers the theoretical
  // case this is ever called before applyWebRiskFusion() has run once -
  // every real call site below calls fusion first, so in practice
  // finalRisk is always already set by the time this runs.
  const finalRisk = record.finalRisk || record.risk;
  if (!finalRisk || finalRisk.verdict !== "HIGH_RISK") return;
  const key = `${tabId}|${record.url}`;
  if (allowedOnce.has(key)) return;
  if (!isCurrent(tabId, record)) return; // stale - a newer navigation has superseded this record
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab || tab.url !== record.url) return; // navigated away already
    let warningUrl =
      chrome.runtime.getURL("warning.html") +
      `?blocked=${encodeURIComponent(record.url)}&score=${finalRisk.riskScore}`;
    // Only attach the Web Risk reason/attribution when THIS verdict was
    // actually produced by a Web Risk match (webRiskOverride === true) -
    // never on a warning that PhishGuard's own ML/heuristics/DOM analysis
    // already reached on its own (spec section 21: "do not incorrectly
    // attach the Google attribution to warnings generated solely from
    // PhishGuard's own ML/heuristics").
    if (finalRisk.webRiskOverride) {
      warningUrl += "&reason=webrisk";
      const threatType = finalRisk.webRisk && finalRisk.webRisk.threatTypes && finalRisk.webRisk.threatTypes[0];
      if (threatType) warningUrl += `&threatType=${encodeURIComponent(threatType)}`;
    }
    await chrome.tabs.update(tabId, { url: warningUrl });
  } catch (e) {
    /* tab may have closed or navigated */
  }
}

// RANK 1: turns the raw hostname/scheme-level chain from
// js/redirectTracker.js into the evidence shape js/riskEngine.js scores,
// adding registrable-domain (PSL-aware) comparison of the ORIGINAL vs FINAL
// URL - not just raw hostname equality, so e.g. "shop.example.co.uk" ->
// "cart.example.co.uk" is correctly recognized as the SAME registrable
// domain (no false "domain changed" signal), matching the same PSL logic
// riskEngine.js's brand-impersonation check already relies on.
//
// RANK 7 (performance): `finalFacts` is the caller's already-computed
// urlFacts() result for `url` itself (see getCachedUrlDerivedFacts() and
// startUrlAnalysis() below). js/redirectTracker.js's summarizeChain()
// always sets `finalUrl` to exactly the `currentUrl` argument it was
// called with - `const finalUrl = currentUrl || chain.finalUrl || originalUrl`
// - and startUrlAnalysis always calls it with `url` itself, so
// `raw.finalUrl === url` is guaranteed, not merely likely. That means a
// fresh `urlFacts(raw.finalUrl)` call here would - always - recompute
// exactly what the caller already has. Passing it in instead removes that
// duplicate PSL/registrable-domain lookup on every redirected navigation.
// Only `originalUrl` (which genuinely differs whenever a real redirect
// occurred) still needs its own fresh urlFacts() call.
async function buildRedirectEvidence(tabId, url, finalFacts) {
  const raw = summarizeChain(tabId, url);
  if (!raw.available) return { available: false };
  if (!raw.redirectCount) {
    // Checked and genuinely clean (a direct, non-redirected load) - not
    // "unknown". Skip the extra urlFacts() call for the common case.
    return { ...raw, registrableDomainChanged: false };
  }
  try {
    const originalFacts = await urlFacts(raw.originalUrl);
    return {
      ...raw,
      originalRegistrableDomain: originalFacts.registrableDomain,
      finalRegistrableDomain: finalFacts.registrableDomain,
      registrableDomainChanged: originalFacts.registrableDomain !== finalFacts.registrableDomain,
    };
  } catch (e) {
    // Enrichment failed - still return the hostname/scheme-level chain
    // facts we do have rather than discarding all redirect evidence.
    return { ...raw, registrableDomainChanged: false };
  }
}

async function startUrlAnalysis(tabId, url) {
  if (!isAnalyzable(url)) {
    tabAnalysis.set(tabId, null);
    nextGeneration(tabId);
    updateBadge(tabId, null);
    return;
  }

  const generation = nextGeneration(tabId); // invalidates any in-flight async work from a prior navigation
  const record = emptyRecord(url, generation);
  tabAnalysis.set(tabId, record);

  // RANK 7 (performance): compute this navigation's URL facts + ML feature
  // object exactly ONCE, up front, and reuse the same result for both the
  // redirect-evidence enrichment below and the ML prediction right after -
  // previously each of those independently re-parsed the same URL from
  // scratch (see getCachedUrlDerivedFacts()'s and buildRedirectEvidence()'s
  // own comments for the full reasoning). This call also warms
  // record._factsCache, so the recomputeRisk() call a few lines down (and
  // every later one triggered by domain/DNS/DOM evidence arriving) reuses
  // this exact same result instead of recomputing it yet again.
  const { facts, mlFeatures } = await getCachedUrlDerivedFacts(record);
  if (!isCurrent(tabId, record)) return; // superseded while parsing the URL (synchronous in practice, but PSL may still be loading on the very first navigation)

  // Rank 1: snapshot whatever redirect chain webNavigation observed for
  // this navigation. Purely local/in-memory (js/redirectTracker.js) - no
  // network dependency, so this never blocks or slows down the fast path
  // below on anything external.
  record.redirect = await buildRedirectEvidence(tabId, url, facts);
  if (!isCurrent(tabId, record)) return; // superseded while gathering redirect evidence

  // Fast local step: URL + ML (no network dependency). Structurally cannot
  // reach HIGH_RISK alone - see js/riskEngine.js weight caps.
  const ml = await predictUrl(url, mlFeatures);
  if (!isCurrent(tabId, record)) return; // superseded by a newer navigation while ML ran
  record.ml = ml;
  await recomputeRisk(record);
  applyWebRiskFusion(record); // record.webRisk is still the "pending" placeholder here - safe passthrough, see emptyRecord()
  updateBadge(tabId, record.finalRisk);
  await maybeRedirectToWarning(tabId, record);

  // Slower, optional steps run in the background and update the record
  // (and badge / warning state) when they resolve. They must never block
  // the fast path above, and their absence must never be treated as safe -
  // each is guarded by isCurrent() so a stale/superseded result is dropped.
  // (`facts`, computed once above, is reused here too - recomputeRisk()
  // sets record.urlFacts to this exact same object, so there is nothing
  // new to read.)

  getDomainIntelligence(facts.registrableDomain).then(async (domain) => {
    if (!isCurrent(tabId, record)) return;
    record.domain = domain;
    await recomputeRisk(record);
    applyWebRiskFusion(record);
    updateBadge(tabId, record.finalRisk);
    maybeRedirectToWarning(tabId, record);
  });

  // EXTERNAL THREAT-INTELLIGENCE VALIDATION LAYER: runs fully in parallel
  // with domain/DNS below, never blocking them or the fast path above (spec
  // section 41). Checks record.url exactly as-is - the URL PhishGuard's own
  // redirect analysis (Rank 1, already captured into record.redirect above)
  // has already settled on as this navigation's destination - so this does
  // NOT create a second redirect-tracking system (spec section 14).
  checkWebRisk(record.url).then(async (webRisk) => {
    if (!isCurrent(tabId, record)) return;
    record.webRisk = webRisk;
    applyWebRiskFusion(record);
    updateBadge(tabId, record.finalRisk);
    await maybeRedirectToWarning(tabId, record);
    notifyPopupOfDomUpdate(tabId); // generic "something changed, re-fetch" push - see that function's own comment
  });

  getDnsRecords(facts.hostname).then(async (dns) => {
    if (!isCurrent(tabId, record)) return;
    record.dns = dns;
    await recomputeRisk(record);
    applyWebRiskFusion(record);
    updateBadge(tabId, record.finalRisk);
    maybeRedirectToWarning(tabId, record);
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    startUrlAnalysis(tabId, changeInfo.url);
  }
});

// RANK 1: chrome.webNavigation and chrome.webRequest are both purely
// observational here (read-only; this extension registers NO "blocking"
// listeners, so no "webRequestBlocking" permission is needed or requested -
// that permission is restricted to force-installed/enterprise extensions
// in MV3 anyway). Two different permissions are required because the
// events genuinely live in two different namespaces:
//   - webNavigation.onBeforeNavigate / onCommitted: real webNavigation
//     events (see Chrome's webNavigation API reference) - used to mark the
//     start of a new top-level navigation and to record where it settled.
//   - webRequest.onBeforeRedirect: NOT a webNavigation event - despite the
//     similar naming, "onBeforeRedirect" only exists on chrome.webRequest
//     (it is not present in chrome.webNavigation at all; that event only
//     surfaces via onCommitted's transitionQualifiers, without hop URLs).
//     This is the only way in MV3 to observe each intermediate hop URL a
//     server-side redirect chain passes through, which is what Rank 1
//     needs. Confirmed against Chrome's official API docs.
// Every handler is scoped to the main frame only (frameId === 0 /
// type === "main_frame"); sub-frame/iframe navigations (ads, embeds,
// widgets) never touch tab-level redirect state. Registered once, at
// module load (same lifetime as every other listener in this file) - never
// re-registered, so there is no risk of duplicate listeners double-counting
// redirects.
//
// DEFENSIVE GUARD: both namespaces are feature-detected before any listener
// is registered. This is NOT here to paper over the bug above (that bug is
// fixed by using the correct namespace) - it exists because a single
// uncaught exception thrown by a top-level statement anywhere in this file
// aborts evaluation of the ENTIRE service worker script, breaking every
// other feature (ML/DOM/domain/DNS analysis, not just redirects), not only
// Rank 1. If either permission is ever unexpectedly inactive - a stale
// reload of an already-loaded unpacked extension after editing
// manifest.json is a common real-world way this happens, since Chrome
// does not always fully re-apply newly ADDED permissions to a running
// unpacked extension until it is removed and reloaded - Rank 1 should
// simply stay off (redirect evidence reports {available:false} and
// riskEngine.js already treats that as "safely continue without it", per
// spec) rather than taking down the whole extension.
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate && chrome.webNavigation.onCommitted) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    resetChain(details.tabId, details.url);
  });

  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    recordCommitted(details.tabId, details.url);
  });
} else {
  console.warn("PhishGuard: chrome.webNavigation unavailable - Rank 1 redirect-chain tracking disabled for this session; all other analysis is unaffected.");
}

if (chrome.webRequest && chrome.webRequest.onBeforeRedirect) {
  chrome.webRequest.onBeforeRedirect.addListener(
    (details) => {
      if (details.frameId !== 0 || details.type !== "main_frame") return;
      recordRedirect(details.tabId, details.url, details.redirectUrl);
    },
    { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] } // required (non-optional) filter for webRequest events
  );
} else {
  console.warn("PhishGuard: chrome.webRequest unavailable - Rank 1 will not see individual redirect hops for this session; all other analysis is unaffected.");
}

chrome.tabs.onRemoved.addListener((tabId) => {
  tabAnalysis.delete(tabId);
  tabGeneration.delete(tabId);
  clearChain(tabId); // Rank 1 - never let a closed tab's redirect chain linger

  // RANK 7 (memory-leak fix): allowedOnce entries were previously only ever
  // added, never pruned - a long browsing session that visits and closes
  // many tabs, each with at least one "proceed anyway" click, grew this Set
  // forever. Every entry is keyed "tabId|url", so once a tab is gone every
  // entry for that tabId is permanently unreachable/meaningless anyway
  // (tab IDs aren't reused while the browser session lives) - safe to drop.
  const prefix = `${tabId}|`;
  for (const key of allowedOnce) {
    if (key.startsWith(prefix)) allowedOnce.delete(key);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PHISHGUARD_DOM_ANALYSIS" && sender.tab) {
    const tabId = sender.tab.id;
    (async () => {
      const msgUrl = message.payload.url;
      let record = tabAnalysis.get(tabId);

      if (record && record.url === msgUrl) {
        // Common case: matches the record we're already tracking.
        if (!isCurrent(tabId, record)) return;
        record.domSignals = message.payload;
        await recomputeRisk(record);
        applyWebRiskFusion(record);
        updateBadge(tabId, record.finalRisk);
        maybeRedirectToWarning(tabId, record);
        notifyPopupOfDomUpdate(tabId);
        return;
      }

      // URL doesn't match our current record - this is EITHER a stale
      // message for a page the tab has since navigated away from, OR a
      // legitimate late-arriving scan (e.g. service worker woke up after
      // content.js already ran). The only reliable way to tell them apart
      // is to check the tab's actual live URL, not just compare strings
      // we already had cached - trusting the message's own URL here was a
      // real bug (a stale message could otherwise overwrite the current,
      // correct record for a since-superseded page).
      if (!isAnalyzable(msgUrl)) return;
      try {
        const tab = await chrome.tabs.get(tabId);
        if (!tab || tab.url !== msgUrl) return; // confirmed stale - tab has moved on, discard
      } catch (e) {
        return; // tab gone or inaccessible - discard
      }

      await startUrlAnalysis(tabId, msgUrl); // creates the record, runs ML, computes initial risk
      const current = tabAnalysis.get(tabId);
      if (!current || current.url !== msgUrl) return; // a newer navigation superseded this during the await
      current.domSignals = message.payload;
      await recomputeRisk(current);
      applyWebRiskFusion(current);
      updateBadge(tabId, current.finalRisk);
      maybeRedirectToWarning(tabId, current);
      notifyPopupOfDomUpdate(tabId);
    })();
    return;
  }

  if (message?.type === "PHISHGUARD_GET_ANALYSIS") {
    const tabId = message.tabId;
    const record = tabAnalysis.get(tabId);
    sendResponse(record || null);
    return true;
  }

  if (message?.type === "PHISHGUARD_PROCEED_ANYWAY") {
    const { tabId, url } = message;
    allowedOnce.add(`${tabId}|${url}`);
    chrome.tabs.update(tabId, { url });
    sendResponse({ ok: true });
    return true;
  }
});

// Re-run analysis when a tab becomes active, in case it was never analyzed
// (e.g. extension was just installed/reloaded).
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const record = tabAnalysis.get(tabId);
  if (record) return;
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.url) startUrlAnalysis(tabId, tab.url);
  } catch (e) {
    /* ignore */
  }
});
