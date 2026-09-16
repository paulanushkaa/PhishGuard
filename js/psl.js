// PhishGuard v5.0 - Public Suffix List based registrable-domain parser.
//
// CRITICAL: Must stay logically identical to training/psl.py. Loads the same
// psl_data.json (real, canonical PSL - both ICANN and PRIVATE sections) used
// by the training pipeline, so brand-impersonation and registrable-domain
// logic behave identically between training-time analysis and browser
// inference. NOT a naive hostname.split(".").slice(-2) heuristic - that
// breaks on co.uk, co.in, com.au, co.jp, github.io, etc.

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_LOOSE_RE = /^[0-9a-fA-F:]+$/;

function isIp(hostname) {
  return IP_RE.test(hostname) || (hostname.includes(":") && IPV6_LOOSE_RE.test(hostname));
}

let _pslPromise = null;

function getPslUrl() {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL) {
    return chrome.runtime.getURL("js/psl_data.json");
  }
  return "./psl_data.json";
}

async function loadPsl() {
  if (!_pslPromise) {
    _pslPromise = (async () => {
      const res = await fetch(getPslUrl());
      if (!res.ok) throw new Error(`Failed to load PSL data: ${res.status}`);
      const data = await res.json();
      return {
        normal: new Set(data.normal),
        wildcardBases: new Set(data.wildcardBases),
        exceptions: new Set(data.exceptions),
      };
    })();
  }
  return _pslPromise;
}

function publicSuffixLen(labels, psl) {
  const n = labels.length;
  for (let i = 0; i < n; i++) {
    const candidateLabels = labels.slice(i);
    const candidate = candidateLabels.join(".");
    if (psl.exceptions.has(candidate)) return n - i - 1;
    if (candidateLabels.length >= 2) {
      const base = candidateLabels.slice(1).join(".");
      if (psl.wildcardBases.has(base)) return n - i;
    }
    if (psl.normal.has(candidate)) return n - i;
  }
  return 1; // default rule "*"
}

/**
 * Returns the eTLD+1 (registrable domain), e.g. "a.b.co.uk" -> "b.co.uk".
 * Requires the PSL to already be loaded (call ensurePslLoaded() once at
 * startup - background.js and any module using this should await it).
 */
export function registrableDomainSync(hostname, psl) {
  if (!hostname) return "";
  hostname = hostname.toLowerCase();
  if (isIp(hostname)) return hostname;
  const labels = hostname.split(".").filter((l) => l);
  if (labels.length <= 1) return hostname;
  const suffixLen = publicSuffixLen(labels, psl);
  const n = labels.length;
  if (suffixLen >= n) return hostname;
  const regLen = suffixLen + 1;
  return labels.slice(n - regLen).join(".");
}

export function publicSuffixSync(hostname, psl) {
  if (!hostname) return "";
  hostname = hostname.toLowerCase();
  if (isIp(hostname)) return hostname;
  const labels = hostname.split(".").filter((l) => l);
  if (labels.length <= 1) return hostname;
  const suffixLen = Math.min(publicSuffixLen(labels, psl), labels.length);
  return labels.slice(labels.length - suffixLen).join(".");
}

let _cachedPsl = null;

/** Call once (e.g. at module init in background.js) to warm the PSL cache. */
export async function ensurePslLoaded() {
  if (!_cachedPsl) _cachedPsl = await loadPsl();
  return _cachedPsl;
}

/**
 * Convenience async wrapper - use when you don't already hold a loaded PSL
 * reference. Prefer ensurePslLoaded() + the *Sync functions in hot paths.
 */
export async function registrableDomain(hostname) {
  const psl = await ensurePslLoaded();
  return registrableDomainSync(hostname, psl);
}

export async function publicSuffix(hostname) {
  const psl = await ensurePslLoaded();
  return publicSuffixSync(hostname, psl);
}

export { isIp };
