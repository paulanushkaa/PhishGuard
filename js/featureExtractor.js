// PhishGuard v5.0 - Canonical URL Feature Extractor (browser inference side)
//
// CRITICAL: This logic must stay IDENTICAL to training/feature_extractor.py.
// Feature order is defined in model/feature_schema.json (schema_version
// 2.0.0). Mismatches here silently corrupt inference.
//
// Changes from v4.0/schema 1.0.0:
//  - is_https REMOVED from the ML feature vector entirely - HTTPS is
//    informational only (see urlFacts()), never scored as ML/risk evidence.
//  - hyphen_count / digit_count / digit_ratio split into hostname_* /
//    path_* variants.
//  - Registrable domain / TLD via the real Public Suffix List (psl.js),
//    not a naive slice(-2) heuristic.
//
// NOTE: extraction is now ASYNC because PSL data is loaded via fetch. The
// PSL is cached after first load, so this is only slow on the very first
// call in a given service-worker lifetime.

import {
  SUSPICIOUS_TLDS, URL_SHORTENERS, SUSPICIOUS_KEYWORDS, SUSPICIOUS_SCHEMES,
  SUSPICIOUS_PORTS,
} from "./config.js";
import { ensurePslLoaded, registrableDomainSync, publicSuffixSync, isIp } from "./psl.js";

export const FEATURE_NAMES = [
  "url_length", "hostname_length", "path_length", "query_length",
  "fragment_length", "path_depth", "num_url_components",
  "hostname_digit_count", "hostname_digit_ratio", "path_digit_count",
  "path_digit_ratio", "dot_count", "hostname_hyphen_count",
  "path_hyphen_count", "underscore_count", "special_char_count",
  "at_count", "percent_count", "equal_count", "amp_count",
  "question_count", "slash_count", "subdomain_count", "max_label_length",
  "hostname_entropy", "url_entropy", "path_entropy", "is_ip_address",
  "is_punycode", "suspicious_tld", "tld_length", "suspicious_port",
  "is_shortener", "has_percent_encoding", "suspicious_scheme",
  "keyword_hit_ratio",
];

function shannonEntropy(s) {
  if (!s) return 0.0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  const len = s.length;
  let ent = 0.0;
  for (const count of freq.values()) {
    const p = count / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

/**
 * Manual string splitter mirroring Python's urllib.parse.urlsplit exactly -
 * see v4.0 changelog for why this replaced the browser URL object (which
 * auto-encodes/re-serializes and silently broke training/inference parity).
 */
function simpleUrlSplit(url) {
  const schemeMatch = url.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\//);
  let scheme = "";
  let rest = url;
  if (schemeMatch) {
    scheme = schemeMatch[1].toLowerCase();
    rest = url.slice(schemeMatch[0].length);
  }

  let authEnd = rest.length;
  for (const ch of ["/", "?", "#"]) {
    const idx = rest.indexOf(ch);
    if (idx !== -1 && idx < authEnd) authEnd = idx;
  }
  const authority = rest.slice(0, authEnd);
  let remainder = rest.slice(authEnd);

  let hostport = authority;
  const atIdx = authority.lastIndexOf("@");
  if (atIdx !== -1) hostport = authority.slice(atIdx + 1);

  let hostname = hostport;
  let port = null;
  if (hostport.startsWith("[")) {
    const closeIdx = hostport.indexOf("]");
    if (closeIdx !== -1) {
      hostname = hostport.slice(1, closeIdx);
      const afterBracket = hostport.slice(closeIdx + 1);
      if (afterBracket.startsWith(":")) {
        const portStr = afterBracket.slice(1);
        if (/^\d+$/.test(portStr)) port = parseInt(portStr, 10);
      }
    }
  } else {
    const colonIdx = hostport.lastIndexOf(":");
    if (colonIdx !== -1) {
      const portStr = hostport.slice(colonIdx + 1);
      if (/^\d+$/.test(portStr)) {
        hostname = hostport.slice(0, colonIdx);
        port = parseInt(portStr, 10);
      }
    }
  }
  hostname = hostname.toLowerCase();

  let fragment = "";
  const hashIdx = remainder.indexOf("#");
  if (hashIdx !== -1) {
    fragment = remainder.slice(hashIdx + 1);
    remainder = remainder.slice(0, hashIdx);
  }
  let query = "";
  const qIdx = remainder.indexOf("?");
  if (qIdx !== -1) {
    query = remainder.slice(qIdx + 1);
    remainder = remainder.slice(0, qIdx);
  }
  const path = remainder;

  return { scheme, hostname, port, path, query, fragment };
}

function normalizeUrlString(rawUrl) {
  let s = (rawUrl || "").trim();
  if (!s) return "http://invalid.invalid";
  if (!/:\/\//.test(s)) s = "http://" + s;
  const parts = simpleUrlSplit(s);
  if (parts.path === "/" && !parts.query && !parts.fragment && s.endsWith("/")) {
    s = s.slice(0, -1);
  }
  return s;
}

/**
 * Returns an ordered object of feature_name -> numeric value, matching
 * FEATURE_NAMES / model/feature_schema.json exactly. ASYNC (loads PSL data
 * on first call, cached thereafter).
 */
export async function extractFeatures(rawUrl) {
  const psl = await ensurePslLoaded();
  const url = normalizeUrlString(rawUrl);
  const parsed = simpleUrlSplit(url);

  const hostname = parsed.hostname;
  const port = parsed.port;
  const path = parsed.path || "";
  const query = parsed.query || "";
  const fragment = parsed.fragment || "";

  const urlLength = url.length;
  const hostnameLength = hostname.length;
  const pathLength = path.length;
  const queryLength = query.length;
  const fragmentLength = fragment.length;
  const pathDepth = path.split("/").filter((seg) => seg !== "").length;
  const numUrlComponents = url.split(/[/?=&]/).filter((seg) => seg !== "").length;

  let hostnameDigitCount = 0;
  for (const ch of hostname) if (ch >= "0" && ch <= "9") hostnameDigitCount++;
  const hostnameDigitRatio = hostnameLength ? hostnameDigitCount / hostnameLength : 0.0;
  let pathDigitCount = 0;
  for (const ch of path) if (ch >= "0" && ch <= "9") pathDigitCount++;
  const pathDigitRatio = pathLength ? pathDigitCount / pathLength : 0.0;

  const dotCount = (url.match(/\./g) || []).length;
  const hostnameHyphenCount = (hostname.match(/-/g) || []).length;
  const pathHyphenCount = (path.match(/-/g) || []).length;
  const underscoreCount = (url.match(/_/g) || []).length;
  const atCount = (url.match(/@/g) || []).length;
  const percentCount = (url.match(/%/g) || []).length;
  const equalCount = (url.match(/=/g) || []).length;
  const ampCount = (url.match(/&/g) || []).length;
  const questionCount = (url.match(/\?/g) || []).length;
  const slashCount = (url.match(/\//g) || []).length;
  const specialCharCount = (url.match(/[^a-zA-Z0-9\-._/:?&=%]/g) || []).length;

  const isIpAddr = isIp(hostname) ? 1 : 0;

  let subdomainCount, maxLabelLength;
  if (isIpAddr) {
    subdomainCount = 0;
    maxLabelLength = hostnameLength;
  } else {
    const labels = hostname.split(".").filter((l) => l);
    subdomainCount = Math.max(0, labels.length - 2);
    maxLabelLength = labels.reduce((m, l) => Math.max(m, l.length), 0);
  }

  const hostnameEntropy = shannonEntropy(hostname);
  const urlEntropy = shannonEntropy(url);
  const pathEntropy = shannonEntropy(path);

  const isPunycode = hostname.includes("xn--") ? 1 : 0;

  const tld = publicSuffixSync(hostname, psl);
  const suspiciousTld = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;
  const tldLength = tld.length;

  const suspiciousPort = port !== null && SUSPICIOUS_PORTS.has(port) ? 1 : 0;

  const regDomain = registrableDomainSync(hostname, psl);
  const isShortener = URL_SHORTENERS.has(regDomain) || URL_SHORTENERS.has(hostname) ? 1 : 0;
  const hasPercentEncoding = url.includes("%") ? 1 : 0;
  const suspiciousScheme = SUSPICIOUS_SCHEMES.has(parsed.scheme) ? 1 : 0;

  const haystack = (hostname + path).toLowerCase();
  let kwHits = 0;
  for (const kw of SUSPICIOUS_KEYWORDS) if (haystack.includes(kw)) kwHits++;
  const keywordHitRatio = SUSPICIOUS_KEYWORDS.length ? kwHits / SUSPICIOUS_KEYWORDS.length : 0.0;

  const values = [
    urlLength, hostnameLength, pathLength, queryLength, fragmentLength,
    pathDepth, numUrlComponents, hostnameDigitCount, hostnameDigitRatio,
    pathDigitCount, pathDigitRatio, dotCount, hostnameHyphenCount,
    pathHyphenCount, underscoreCount, specialCharCount, atCount,
    percentCount, equalCount, ampCount, questionCount, slashCount,
    subdomainCount, maxLabelLength, hostnameEntropy, urlEntropy, pathEntropy,
    isIpAddr, isPunycode, suspiciousTld, tldLength, suspiciousPort,
    isShortener, hasPercentEncoding, suspiciousScheme, keywordHitRatio,
  ];

  const out = {};
  FEATURE_NAMES.forEach((name, i) => (out[name] = values[i]));
  return out;
}

/** Returns the feature vector as a plain array, in FEATURE_NAMES order. */
export async function extractFeatureVector(rawUrl) {
  const feats = await extractFeatures(rawUrl);
  return FEATURE_NAMES.map((name) => feats[name]);
}

/** Non-ML facts reused by riskEngine.js for explanations and the
 * brand-impersonation heuristic. HTTPS is included here ONLY as an
 * informational fact - it is never treated as risk evidence. */
export async function urlFacts(rawUrl) {
  const psl = await ensurePslLoaded();
  const url = normalizeUrlString(rawUrl);
  const parsed = simpleUrlSplit(url);
  const hostname = parsed.hostname;
  const registrableDomain = registrableDomainSync(hostname, psl);
  const tld = publicSuffixSync(hostname, psl);
  return {
    normalizedUrl: url,
    hostname,
    registrableDomain,
    tld,
    scheme: parsed.scheme,
    isHttps: parsed.scheme === "https",
    isIpAddress: isIp(hostname),
    isShortener: URL_SHORTENERS.has(registrableDomain) || URL_SHORTENERS.has(hostname),
    suspiciousTld: SUSPICIOUS_TLDS.has(tld),
    // RANK 6 (URL feature engineering): path/query/fragment, already parsed
    // above by simpleUrlSplit() - returned here (not re-parsed) so
    // riskEngine.js's new URL-heuristic checks (query-parameter count,
    // redirect-parameter cross-domain detection, repeated path-segment
    // detection) never need a second URL parser. Non-ML facts only - see
    // this function's own docstring; the ML feature vector above is
    // unaffected.
    path: parsed.path || "",
    query: parsed.query || "",
    fragment: parsed.fragment || "",
  };
}
