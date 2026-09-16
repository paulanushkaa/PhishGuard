// PhishGuard v5.1 - Redirect-chain + final-destination tracker (Rank 1).
//
// Populated from TWO Chrome APIs, both used strictly for observation (this
// module registers no blocking listeners and cannot itself affect
// navigation):
//   - chrome.webNavigation.onBeforeNavigate / onCommitted - mark the start
//     of a new top-level navigation and record where it settles.
//   - chrome.webRequest.onBeforeRedirect - the ONLY MV3 API that exposes
//     each individual intermediate hop URL of a server-side redirect
//     chain. Despite the similar name, this event does NOT exist on
//     chrome.webNavigation (confirmed against Chrome's official API
//     reference) - webNavigation only ever tells you a redirect happened,
//     via a transitionQualifier on the eventual onCommitted, without the
//     hop URLs this module needs.
// See background.js's listener-registration block for the corresponding
// "webNavigation" + "webRequest" manifest permissions and the reasoning
// for each.
//
// PERMISSION: this rank requires "webNavigation" AND "webRequest" in
// manifest.json's permissions. Both are read-only/observational here - no
// "webRequestBlocking" is used or requested (that permission is restricted
// to force-installed/enterprise extensions under MV3 and isn't needed
// anyway, since this module never blocks or modifies a request). Together
// they expose exactly what this module needs - navigation lifecycle
// timing and redirect-hop URLs - and nothing about request/response
// bodies or headers.
//
// SAFETY:
//  - Isolated per tab (Map keyed by tabId) - one tab's chain can never leak
//    into another's.
//  - Reset on every new top-level navigation (onBeforeNavigate, frameId 0
//    only - sub-frame/iframe navigations never touch this state), so stale
//    data from a previous page can never bleed into the next one.
//  - Cleared explicitly on tab close (see clearChain(), called from
//    background.js's existing chrome.tabs.onRemoved listener) - no entry
//    ever outlives its tab.
//  - Hop storage is capped (MAX_TRACKED_HOPS) so a redirect loop or a
//    pathological/adversarial chain can never grow this module's memory
//    footprint or the derived analysis unboundedly. The redirect COUNT is
//    still tracked accurately beyond the cap; only per-hop URL storage
//    stops growing.
//  - Never throws: malformed URLs are handled defensively and simply drop
//    out of the scheme/hostname comparisons rather than raising.
//  - Purely additive/observational - never calls any blocking or
//    navigation-modifying API, so normal page navigation is never affected.

const MAX_TRACKED_HOPS = 20;

const chains = new Map(); // tabId -> { originalUrl, hops: [{url, at}], finalUrl, redirectCount }

function schemeOf(url) {
  try {
    return new URL(url).protocol.replace(":", "");
  } catch (e) {
    return null;
  }
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (e) {
    return null;
  }
}

/** Called from chrome.webNavigation.onBeforeNavigate (main frame only) -
 * starts a fresh chain for a new top-level navigation. */
export function resetChain(tabId, url) {
  chains.set(tabId, { originalUrl: url, hops: [], finalUrl: url, redirectCount: 0 });
}

/** Called from chrome.webNavigation.onBeforeRedirect (main frame only). */
export function recordRedirect(tabId, fromUrl, toUrl) {
  let chain = chains.get(tabId);
  if (!chain) {
    // We missed onBeforeNavigate (e.g. the service worker was asleep and
    // just woke up mid-flight) - start a best-effort chain from what we
    // actually observed rather than dropping the evidence entirely.
    chain = { originalUrl: fromUrl, hops: [], finalUrl: fromUrl, redirectCount: 0 };
    chains.set(tabId, chain);
  }
  if (chain.hops.length < MAX_TRACKED_HOPS) {
    chain.hops.push({ url: toUrl, at: Date.now() });
  }
  chain.finalUrl = toUrl;
  chain.redirectCount += 1;
}

/** Called from chrome.webNavigation.onCommitted (main frame only) - records
 * the URL the navigation actually settled on (belt-and-braces alongside the
 * redirectCount-derived finalUrl above; these should normally agree). */
export function recordCommitted(tabId, url) {
  const chain = chains.get(tabId);
  if (chain) chain.finalUrl = url;
}

/** Called from background.js's existing chrome.tabs.onRemoved listener. */
export function clearChain(tabId) {
  chains.delete(tabId);
}

/**
 * Summarizes the tracked chain into the plain-data shape js/riskEngine.js
 * expects, WITHOUT any PSL/registrable-domain knowledge (this module has
 * none - that enrichment is added by the caller in background.js using
 * js/featureExtractor.js's urlFacts(), which already owns PSL loading).
 *
 * Returns { available: false } when nothing was observed for this tab at
 * all (e.g. webNavigation events haven't fired yet, or this is being asked
 * about a non-web-navigable page). A direct, single-URL load with zero
 * redirects is NOT the same thing - that case returns
 * { available: true, redirectCount: 0, ... }, which riskEngine.js must
 * treat as "checked, nothing suspicious", not "unknown".
 */
export function summarizeChain(tabId, currentUrl) {
  const chain = chains.get(tabId);
  if (!chain) return { available: false };

  const originalUrl = chain.originalUrl || currentUrl;
  const finalUrl = currentUrl || chain.finalUrl || originalUrl;

  const urlsInOrder = [originalUrl, ...chain.hops.map((h) => h.url)];
  if (urlsInOrder[urlsInOrder.length - 1] !== finalUrl) urlsInOrder.push(finalUrl);

  let hostnameChanges = 0;
  let httpChanges = 0;
  let httpsToHttpDowngrade = false;
  let prevHost = hostnameOf(urlsInOrder[0]);
  let prevScheme = schemeOf(urlsInOrder[0]);

  for (let i = 1; i < urlsInOrder.length; i++) {
    const host = hostnameOf(urlsInOrder[i]);
    const scheme = schemeOf(urlsInOrder[i]);
    if (host && prevHost && host !== prevHost) hostnameChanges++;
    if (scheme && prevScheme && scheme !== prevScheme) {
      httpChanges++;
      if (prevScheme === "https" && scheme === "http") httpsToHttpDowngrade = true;
    }
    if (host) prevHost = host;
    if (scheme) prevScheme = scheme;
  }

  return {
    available: true,
    originalUrl,
    finalUrl,
    urlsInOrder: urlsInOrder.slice(0, MAX_TRACKED_HOPS + 1),
    redirectCount: Math.max(chain.redirectCount || 0, urlsInOrder.length - 1),
    hostnameChanges,
    httpChanges,
    httpsToHttpDowngrade,
  };
}
