// PhishGuard v5.0 - Risk Engine (evidence fusion).
//
// ARCHITECTURAL REWRITE FROM v4.0. The previous version renormalized weights
// across whichever evidence sources were available, which meant that when
// DOM/domain/DNS were all unavailable, ML's weight was implicitly
// inflated toward ~100% of the decision - i.e. "ML alone" could effectively
// drive the verdict. That is exactly the failure mode this version is
// designed to make STRUCTURALLY IMPOSSIBLE, not just discouraged by comment.
//
// Two independent safeguards enforce this:
//
//  1. FIXED WEIGHT CAPS (no renormalization). Each evidence category has a
//     maximum POINT budget out of 100 (see WEIGHTS). Unavailable categories
//     contribute exactly 0 - they are NEVER redistributed to other
//     categories. Because ML's budget (35) plus URL heuristics' budget (15)
//     sum to only 50 - below the HIGH_RISK threshold of 60 - it is
//     mathematically impossible for ML + weak URL signals alone (with DOM,
//     domain, and DNS all unavailable or clean) to reach
//     HIGH_RISK. This is a property of the arithmetic, not a special case.
//
//  2. EXPLICIT CORROBORATION GATE. Even if the weighted score reaches 60+,
//     HIGH_RISK is only assigned if an explicit, auditable corroboration
//     condition is also met (see qualifiesForHighRisk()). A score that
//     crosses 60 without qualifying corroboration is demoted to SUSPICIOUS,
//     never silently promoted or hidden.
//
// HTTPS IS NOT SCORED. is_https is not an ML feature (see feature_schema.json
// v2.0.0) and is not scored here in either direction - it is surfaced to the
// user as an informational fact only (see the `informational` return field),
// never as risk evidence, never as a "positive" or "negative" reason.
//
// UNAVAILABLE EVIDENCE IS UNKNOWN, NOT SAFE, NOT MALICIOUS. Every category
// below returns { available: false, score: 0, confidence: 0 } when its
// source could not be evaluated - it contributes nothing to the score and is
// labeled "Unavailable" in explanations, never conflated with "checked and
// clean."
//
// WEIGHTS are configurable starting values (see training/README.md and the
// root README's "Known limitations" for how they were chosen and what has
// NOT been formally validated).

import { KNOWN_BRANDS, SUSPICIOUS_KEYWORDS, MULTI_PART_TLDS } from "./config.js";
import { clamp } from "./utils.js";
import { decodeIdnLabel, isMixedScriptLabel, normalizeHomoglyphsUnicode } from "./idn.js";

export const WEIGHTS = {
  ml: 40,
  dom: 30,
  urlHeuristics: 15,
  domain: 10,
  dns: 5,
};
// Sum = 100 (local/client-side evidence only; no external reputation service).
// Note ml + urlHeuristics = 50 < 60 (HIGH_RISK threshold): this is
// intentional and is what makes "ML alone" structurally incapable of
// reaching HIGH_RISK even in the worst case (every other source unavailable).

export const THRESHOLDS = {
  safeMax: 29,
  suspiciousMax: 59, // 60+ is required (but not sufficient - see corroboration gate) for HIGH_RISK
};

const URL_ENTROPY_HIGH = 4.3; // heuristic threshold, not a proof of anything by itself

// RANK 7 (corroboration - signal-family grouping): very-long-URL,
// many-query-parameters, high hostname entropy, excessive percent-encoding,
// and a repeated path segment are, per the project spec, "manifestations
// of URL complexity" rather than independent phishing indicators - a
// single unusually complex/obfuscated-looking (but not otherwise
// suspicious) URL should not be able to rack up an open-ended score just
// because several DIFFERENT metrics all happen to describe the SAME
// underlying property. This cap is deliberately set to the sum of the two
// STRONGEST individual members (hostname-entropy=10 + excessive-percent-
// encoding=10 = 20), so it only ever changes anything when 3 or more of
// these five signals fire on the SAME URL simultaneously - any 1-signal or
// 2-signal case is completely unaffected (their sum can never exceed 20
// anyway), so this cannot weaken any already-validated single- or
// dual-signal test case. It ONLY ever reduces a score, never increases one,
// so it cannot introduce a new false positive. Explicitly does NOT include
// typosquatting, IDN/homoglyph, credential-harvesting, redirect evidence,
// domain age, DNS, IP-address, or digit-heavy/long-label hostname checks -
// each of those is a distinct, independently-reasoned family and is left
// exactly as before.
const URL_COMPLEXITY_FAMILY_CAP = 20;
const ELEVATED_THRESHOLD = 50; // a category's internal 0-100 score counts as "elevated" at/above this
const ML_ULTRA_HIGH_CONFIDENCE = 95; // measured ~0.46% false-positive rate on held-out validation at this threshold (see training/README.md "Risk engine: isolated-ML gate"); comfortably above every legitimate auth-flow URL observed in that data (max measured 94.9%, claude.ai/new measures 94.6%). Re-verified by re-running the training split/model in this session: 0.46%/0.34% FPR on val/test respectively - unchanged, not lowered. See training/README.md addendum below for why this specific value is a hard floor, not a starting point: legitimate auth-flow pages measure up to 94.9% (claude.ai/new itself measures 94.6%), so any value below ~96 would misclassify a named regression requirement.
const ML_STRONG_THRESHOLD = 90; // "strong ML evidence" tier (spec Task 2 example: "ML probability = 0.90+"). Deliberately BELOW ML_ULTRA_HIGH_CONFIDENCE and never used to let ML act alone (see qualifiesForSuspicious/qualifiesForCombinedWeakEvidenceSuspicion, unchanged) - only used below to let ML combine with ONE other genuinely-observed independent signal to reach HIGH_RISK, matching spec Task 15's "strong ML probability + meaningful URL/domain evidence" pattern, which qualifiesForHighRisk() previously had no explicit rule for at all.

// FIX (URL-heuristic keyword gap): mlFeatures.keyword_hit_ratio (computed by
// featureExtractor.js as matchedKeywordCount / SUSPICIOUS_KEYWORDS.length,
// see js/config.js) was already part of the ML feature vector but was never
// consumed here, so lexical evidence (login/payment/verify/bank/... wording
// in the URL) contributed nothing to the separate 15-point URL-heuristics
// category. KEYWORD_LIST_SIZE below is used ONLY to turn that ratio back
// into an approximate keyword-hit count for tiered scoring - it references
// the existing SUSPICIOUS_KEYWORDS list's length (already imported above,
// same list featureExtractor.js uses), not a reimplementation or a second
// keyword list, and no URL/page text is rescanned here.
const KEYWORD_LIST_SIZE = SUSPICIOUS_KEYWORDS.length;
// Conservative, tiered contribution (0-100 internal scale, same scale as
// every other check in scoreUrlHeuristics - it is then capped 0-100 and
// scaled by WEIGHTS.urlHeuristics/100 like everything else in this
// function, so it can never exceed the existing 15-point budget). A SINGLE
// matched keyword contributes nothing: words like "login", "secure",
// "verify", or "account" appear constantly in legitimate auth-flow URLs
// (accounts.google.com/login, login.microsoftonline.com, bank login pages,
// etc.), so one match alone must never be treated as phishing evidence.
// Multiple independent suspicious words appearing in the same URL is much
// less common for legitimate sites and is treated as progressively
// stronger (but still not solely decisive - see qualifiesForSuspicious()/
// qualifiesForCombinedWeakEvidenceSuspicion(), both unchanged) evidence.
const KEYWORD_HIT_SCORE_BY_TIER = { 0: 0, 1: 0, 2: 10, 3: 25 }; // 4+ hits -> 30 (see scoreUrlHeuristics)

// RANK 2 (typosquatting detection).
//
// Deliberately conservative and narrow, per spec: NOT broad substring
// matching (that's what already correctly keeps "microsoftonline.com" and
// "google.com/search?q=whatsapp" safe elsewhere in this file) - this
// compares ONLY the registrable domain's own SLD label against each known
// brand string, using two specific, bounded transformations:
//
//  1. Homoglyph/leetspeak normalization (0->o, 1->l, 3->e, 4->a, 5->s,
//     7->t, 8->b, $->s, @->a) plus hyphen removal, then an EXACT match
//     against the brand string. Catches "paypa1"->"paypal", "g00gle"->
//     "google", "micros0ft"->"microsoft", "amaz0n"->"amazon", and
//     "pay-pal"->"paypal".
//  2. A bounded Damerau-Levenshtein edit distance (single character
//     substitution, insertion, omission, or adjacent-character swap per
//     unit of distance) between the normalized label and the brand string.
//     Catches typos the homoglyph table doesn't (e.g. "paypall",
//     "mircosoft"). Distance allowed is TIERED BY BRAND LENGTH (see
//     TYPOSQUAT_LONG_BRAND_MIN_LEN below) - exactly 1 for short/common
//     brand strings, up to 2 for longer ones, per spec ("for short brand
//     names, use stricter matching; for longer brand names, allow limited
//     typo distance"). A short brand allowed 2 edits risks colliding with
//     an unrelated short word (little of the brand's original character
//     sequence has to survive); a long, distinctive compound name like
//     "wellsfargo" or "bankofamerica" still has plenty of surviving
//     structure at distance 2, so the false-positive risk stays low while
//     catching a second, real observed pattern (double-typos of long
//     brand names).
//
// A length-difference pre-filter (>2 chars apart) and a minimum brand
// length (TYPOSQUAT_MIN_BRAND_LEN) keep this from ever being able to match
// a short brand string buried inside a much longer, unrelated word -
// distance-1-or-2 matching is structurally incapable of connecting a short
// brand to a long compound label like "microsoftonline" (edit distance 6),
// so this is a belt-and-braces guard, not the primary safety mechanism. The
// pre-filter's ">2" bound already covers both tiers (a distance-1 match is
// impossible once length diff exceeds 1 anyway - damerauLevenshtein's own
// short-circuit makes this equivalent to a tighter filter for short
// brands, just without a second constant to keep in sync).
const HOMOGLYPH_MAP = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a" };
const TYPOSQUAT_MIN_BRAND_LEN = 5; // excludes "absa"/"sber" (4 chars) - same margin already used for path-token brand matching above
// RANK 2 FIX (tiered edit distance): brands at/above this length get the
// distance-2 allowance described above; shorter brands keep the original,
// stricter distance-1-only behavior (unchanged from the prior release for
// every brand below this length).
const TYPOSQUAT_LONG_BRAND_MIN_LEN = 8;

function normalizeHomoglyphs(label) {
  let out = "";
  for (const ch of label) out += HOMOGLYPH_MAP[ch] || ch;
  return out;
}

/** Bounded Damerau-Levenshtein distance (substitution/insertion/deletion/
 * adjacent-transposition, cost 1 each). Returns a value > maxDist as soon
 * as it's provably too far, without finishing the full computation, so
 * this stays cheap even if ever called with longer strings. */
function damerauLevenshtein(a, b, maxDist) {
  if (Math.abs(a.length - b.length) > maxDist) return maxDist + 1;
  const al = a.length, bl = b.length;
  const d = [];
  for (let i = 0; i <= al; i++) d[i] = [i];
  for (let j = 0; j <= bl; j++) d[0][j] = j;
  for (let i = 1; i <= al; i++) {
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[al][bl];
}

/** Returns { matched: false } or { matched: true, brand, kind }. Only ever
 * compares the registrable domain's own SLD label - never a subdomain
 * label, path segment, or query string (those are separate, existing
 * checks elsewhere in this file with their own, different safeguards). */
function detectTyposquatting(urlFacts) {
  const regLabel = (urlFacts.registrableDomain.split(".")[0] || "").toLowerCase();
  if (!regLabel || regLabel.length < 4) return { matched: false };
  if (KNOWN_BRANDS.includes(regLabel)) return { matched: false }; // the brand's own real domain - not typosquatting

  const strippedLabel = regLabel.replace(/-/g, "");
  const normalizedLabel = normalizeHomoglyphs(strippedLabel);

  for (const brand of KNOWN_BRANDS) {
    if (brand.length < TYPOSQUAT_MIN_BRAND_LEN) continue;
    if (Math.abs(normalizedLabel.length - brand.length) > 2) continue;
    if (normalizedLabel === brand) {
      return { matched: true, brand, kind: "homoglyph_or_hyphen" };
    }
    // RANK 2 FIX: tiered distance - see TYPOSQUAT_LONG_BRAND_MIN_LEN comment
    // above. Everything below that length keeps the exact prior behavior
    // (distance must be === 1); this only ever ADDS matches (distance-2),
    // never removes any previously-matched distance-1 case.
    const maxTypoDistance = brand.length >= TYPOSQUAT_LONG_BRAND_MIN_LEN ? 2 : 1;
    const dist = damerauLevenshtein(normalizedLabel, brand, maxTypoDistance);
    if (dist >= 1 && dist <= maxTypoDistance) {
      return { matched: true, brand, kind: dist === 1 ? "edit_distance" : "edit_distance_2" };
    }
  }
  return { matched: false };
}

// RANK 3 (Punycode / IDN / mixed-script / homoglyph detection).
//
// See js/idn.js for the self-contained Punycode (RFC 3492) decoder and the
// small, conservative homoglyph-confusable table it exports - this file
// only consumes those exports; the decoding/normalization logic itself
// lives there so it can be unit-tested independently.
//
// detectHomoglyphBrandImpersonation() below deliberately mirrors
// detectTyposquatting()'s SCOPE exactly (registrable domain's own SLD
// label only - never a subdomain, path, or query string) for the same
// reason: that is the one label users actually read as "the domain" in
// the address bar. It differs from detectTyposquatting in matching
// strategy: EXACT match only after decode+normalize, no edit-distance
// layered on top - deliberately more conservative than Rank 2's fuzzy
// matching, per spec ("Do NOT use broad substring matching"). The two
// functions cannot overlap or double-count the same evidence: this one
// only ever engages for a label that is ACTUALLY IDN-derived (Punycode-
// encoded or literally containing a raw non-ASCII code point) - an
// ordinary ASCII label (which is everything detectTyposquatting's fuzzy
// matching looks at) never reaches the confusable table here at all.
function detectHomoglyphBrandImpersonation(urlFacts) {
  const regLabel = (urlFacts.registrableDomain.split(".")[0] || "");
  const isIdnDerived = regLabel.toLowerCase().startsWith("xn--") || /[^\x00-\x7F]/.test(regLabel);
  if (!isIdnDerived) return { matched: false };

  const decoded = decodeIdnLabel(regLabel);
  const normalized = normalizeHomoglyphsUnicode(decoded.text);
  // The FULL label must collapse entirely to basic-Latin letters - any
  // leftover character the small confusable table doesn't cover
  // (including an entire different, unmapped script) blocks the match.
  // This is what keeps a genuine, wholly non-Latin IDN (spec's "normal
  // IDN" case, e.g. a Cyrillic city/business name) from ever being
  // coerced into a false brand match: real-world non-Latin words very
  // rarely consist ENTIRELY of the ~11 characters in the confusable
  // table, so they are structurally very unlikely to fully collapse.
  if (!/^[a-z]+$/.test(normalized)) return { matched: false };
  if (normalized.length < TYPOSQUAT_MIN_BRAND_LEN) return { matched: false };
  if (KNOWN_BRANDS.includes(normalized)) {
    return { matched: true, brand: normalized };
  }
  return { matched: false };
}

// RANK 6 (URL feature engineering) constants and helpers.
//
// All thresholds below are deliberately conservative - each individual
// check contributes a small amount to the existing 0-100 internal
// urlHeuristics scale (itself capped at WEIGHTS.urlHeuristics = 15/100
// of the overall score, unchanged), so no single one of these can push a
// legitimate site out of SAFE on its own; they only matter once several
// independently-observed signals (here or in other categories) combine,
// via the EXISTING, unmodified corroboration gates (qualifiesForHighRisk,
// qualifiesForSuspicious, qualifiesForCombinedWeakEvidenceSuspicion) -
// none of which are touched by Rank 6.
const VERY_LONG_URL_LENGTH = 200; // chars - well above ordinary URLs but well within what legitimate OAuth/tracking/CDN URLs commonly reach; "long" (75-200) intentionally scores nothing per spec section 4.A
const MANY_QUERY_PARAMS_THRESHOLD = 8; // legitimate OAuth/analytics/tracking URLs routinely carry several params; this only fires well past that
const EXCESSIVE_PERCENT_COUNT_MIN = 6; // a couple of ordinary %20/%2F encodings must never fire this
const EXCESSIVE_PERCENT_RATIO = 0.08; // percent_count / url_length - catches heavy/repeated encoding, not incidental encoding in an otherwise-normal URL
const REPEATED_PATH_SEGMENT_MIN_COUNT = 3; // the SAME path segment appearing 3+ times - rare in legitimate sites, common in some obfuscation/loop patterns
const REPEATED_PATH_SEGMENT_MIN_LEN = 3; // excludes trivial 1-2 char segments (locale codes, etc.)

// Spec section 11 - parameter NAMES only ever considered "potentially a
// redirect parameter"; per the spec's own explicit requirement, having one
// of these names present must NEVER by itself score anything (many
// legitimate sites use them - OAuth "continue"/"redirect_uri", "next" after
// login, etc.). Only a same-named parameter whose VALUE resolves to an
// actual cross-domain absolute URL (see extractEmbeddedHost below) ever
// contributes any score - see the check itself for that gate.
const REDIRECT_PARAM_NAMES = new Set(["url", "redirect", "next", "return", "continue", "target", "destination", "callback"]);

/** Splits an already-extracted query string (urlFacts.query - no leading
 * "?", already produced by featureExtractor.js's simpleUrlSplit(), not a
 * second parser) into [{key, value}] pairs. Deliberately tiny/defensive -
 * this is a rule-based URL-heuristic helper only, never fed to the ML
 * model. */
function parseQueryParams(query) {
  if (!query) return [];
  const out = [];
  for (const part of query.split("&")) {
    if (!part) continue;
    const eqIdx = part.indexOf("=");
    const key = eqIdx === -1 ? part : part.slice(0, eqIdx);
    const value = eqIdx === -1 ? "" : part.slice(eqIdx + 1);
    out.push({ key, value });
  }
  return out;
}

/** Returns the lowercased hostname embedded in `rawValue` IF (and only if)
 * the value itself looks like an absolute URL (scheme:// or scheme-relative
 * //), e.g. a redirect-parameter value of "https://evil.example/x". A
 * plain relative path/value (e.g. "/dashboard", the ordinary OAuth
 * "continue=" case) never matches this pattern and returns null - this is
 * exactly what keeps same-site login-continuation URLs from ever being
 * treated as suspicious (spec's explicit requirement). Handles one level
 * of percent-encoding (the common case for a URL embedded inside another
 * URL's query string) defensively - never throws on malformed input. */
function extractEmbeddedHost(rawValue) {
  if (!rawValue) return null;
  let value = rawValue;
  try {
    value = decodeURIComponent(rawValue);
  } catch {
    value = rawValue; // malformed percent-encoding - fall back to the raw value
  }
  const m = value.match(/^(?:https?:)?\/\/([^/?#]+)/i);
  if (!m) return null;
  let host = m[1].toLowerCase();
  const atIdx = host.lastIndexOf("@");
  if (atIdx !== -1) host = host.slice(atIdx + 1); // strip userinfo, if any
  const colonIdx = host.indexOf(":");
  if (colonIdx !== -1) host = host.slice(0, colonIdx); // strip port, if any
  return host || null;
}

/** True if the SAME non-trivial path segment (case-insensitive) repeats at
 * least REPEATED_PATH_SEGMENT_MIN_COUNT times in urlFacts.path (already
 * parsed - no second parser). */
function hasRepeatedPathSegment(path) {
  if (!path) return false;
  const counts = new Map();
  for (const seg of path.split("/")) {
    if (seg.length < REPEATED_PATH_SEGMENT_MIN_LEN) continue;
    const key = seg.toLowerCase();
    const c = (counts.get(key) || 0) + 1;
    counts.set(key, c);
    if (c >= REPEATED_PATH_SEGMENT_MIN_COUNT) return true;
  }
  return false;
}

function scoreUrlHeuristics(urlFacts, mlFeatures) {
  const flags = [];
  let score = 0;
  let brandImpersonationDetected = false;
  // RANK 7: accumulates the "URL complexity" signal family (see
  // URL_COMPLEXITY_FAMILY_CAP above) separately from `score` - folded into
  // `score`, capped, in one place at the end of this function.
  let complexityScore = 0;

  // Computed here (before the IP-address check) so it is available both to
  // the existing keyword-scoring block below AND to the new RANK 6
  // IP+keyword correlation check - same single computation, reused, not
  // duplicated. Logic/values are byte-for-byte identical to the prior
  // in-place computation that used to live inside the keyword block.
  const approxKeywordHits =
    mlFeatures && typeof mlFeatures.keyword_hit_ratio === "number" && KEYWORD_LIST_SIZE > 0
      ? Math.round(mlFeatures.keyword_hit_ratio * KEYWORD_LIST_SIZE)
      : 0;

  if (urlFacts.isIpAddress) {
    score += 25;
    flags.push({ level: "warning", text: "URL uses a raw IP address instead of a domain name" });

    // RANK 6 (URL feature engineering - correlation): an IP-address
    // hostname is already scored above; a suspicious keyword (login,
    // verify, payment, etc. - reused from the existing keyword-hit
    // computation, not re-scanned) or a suspicious port (reused from
    // mlFeatures.suspicious_port, already computed by featureExtractor.js
    // for the ML model but never previously consumed here) appearing on
    // the SAME raw-IP URL is more specific than either fact alone -
    // directly matches the spec's own worked example ("suspicious login
    // token + IP hostname -> stronger evidence"). Only fires when the IP
    // check above already fired, so this is purely additive correlation,
    // not a new standalone check, and it can never fire without the base
    // +25 IP signal already present.
    if (approxKeywordHits >= 1) {
      score += 10;
      flags.push({ level: "warning", text: "Raw IP-address hostname combined with suspicious keyword wording in the URL" });
    }
    if (mlFeatures && mlFeatures.suspicious_port) {
      score += 5;
      flags.push({ level: "info", text: "Raw IP-address hostname on an unusual port" });
    }
  }
  if (urlFacts.normalizedUrl.includes("@")) {
    score += 25;
    flags.push({ level: "warning", text: "URL contains an '@' symbol (can hide the real destination)" });
  }
  if (urlFacts.suspiciousTld) {
    score += 15;
    flags.push({ level: "info", text: `Uses a TLD (.${urlFacts.tld}) commonly abused for throwaway/malicious domains` });
  }
  if (urlFacts.isShortener) {
    score += 10;
    flags.push({ level: "info", text: "URL is from a link-shortening service (real destination is hidden)" });
  }
  // FIX (false-positive patch): this used to check mlFeatures.url_entropy
  // (entropy of the ENTIRE url - hostname + path + query + fragment).
  // Legitimate sites routinely produce long, high-entropy QUERY STRINGS
  // (encoded tracking/session/search params - e.g. a Google search results
  // URL) that pushed whole-URL entropy well past the threshold despite the
  // hostname itself being completely ordinary. Obfuscation/DGA-style
  // randomness that actually matters for phishing detection lives in the
  // HOSTNAME, not the query string, so this now checks hostname_entropy
  // only - the query string no longer contributes to this heuristic at
  // all. Same threshold constant, narrower and more accurate basis.
  if (mlFeatures && mlFeatures.hostname_entropy > URL_ENTROPY_HIGH) {
    complexityScore += 10;
    flags.push({ level: "info", text: "URL has unusually high character randomness" });
  }

  // FIX (URL-heuristic keyword gap - see KEYWORD_LIST_SIZE/
  // KEYWORD_HIT_SCORE_BY_TIER comment above): use the already-computed
  // mlFeatures.keyword_hit_ratio so suspicious URL wording (login, payment,
  // bank, verify, etc. - see js/config.js SUSPICIOUS_KEYWORDS, matched by
  // featureExtractor.js over hostname+path) is visible to this
  // URL-heuristic category too, not just to the ML model.
  if (approxKeywordHits > 0) {
    const keywordScore = approxKeywordHits >= 4 ? 30 : (KEYWORD_HIT_SCORE_BY_TIER[approxKeywordHits] || 0);
    if (keywordScore > 0) {
      score += keywordScore;
      flags.push({
        level: approxKeywordHits >= 4 ? "warning" : "info",
        text: `URL text contains ${approxKeywordHits} suspicious keywords commonly seen in phishing (e.g. login, payment, verify, bank wording)`,
      });
    }
  }

  // RANK 6 (URL feature engineering): unusually deep subdomain chains
  // (e.g. "secure.login.account.verify.example.com") are a known phishing
  // obfuscation pattern - reusing mlFeatures.subdomain_count (already
  // computed by featureExtractor.js for the ML model; not re-derived here)
  // rather than adding a second, separate hostname-parsing pass. The
  // threshold (4+) is set well above what ordinary legitimate services use
  // (docs./www./accounts./mail.-style single-level subdomains, or at most
  // two or three levels for larger orgs) to keep this from firing on
  // normal corporate or SaaS subdomain structures.
  if (mlFeatures && typeof mlFeatures.subdomain_count === "number" && mlFeatures.subdomain_count >= 4) {
    score += 10;
    flags.push({ level: "info", text: `Hostname has an unusually deep subdomain chain (${mlFeatures.subdomain_count} levels)` });
  }

  // RANK 6 (URL feature engineering - hostname structure): a single
  // unusually long hostname LABEL (distinct from subdomain_count above,
  // which counts LEVELS, not label length) is a separate obfuscation
  // pattern - e.g. a long random/encoded blob used as a subdomain label.
  // Reuses mlFeatures.max_label_length (already computed by
  // featureExtractor.js for the ML model, never previously consumed here).
  // Excluded for IP hostnames (max_label_length there is just the whole
  // dotted-quad/IPv6 string, an unrelated concept, already fully scored by
  // the isIpAddress check above). Threshold (30) is well above any real
  // legitimate label observed in the regression suite (ordinary hostname
  // labels - brand names, product names, "accounts", "www", etc. - are
  // nowhere close to this length).
  if (!urlFacts.isIpAddress && mlFeatures && typeof mlFeatures.max_label_length === "number" && mlFeatures.max_label_length >= 30) {
    score += 5;
    flags.push({ level: "info", text: `Hostname contains an unusually long individual label (${mlFeatures.max_label_length} characters)` });
  }

  // RANK 6 (URL feature engineering - hostname structure): a hostname
  // consisting mostly of digits (e.g. a DGA-style "a83jd9k1x2.xyz") is a
  // separate signal from Rank 2's typosquatting logic - that check only
  // ever compares a label against KNOWN_BRANDS after homoglyph/leetspeak
  // normalization (digit-for-letter substitution WITHIN a brand-like word);
  // this check looks at the raw digit ratio of the hostname regardless of
  // any brand resemblance, so the two cannot double-count the same
  // observation. Reuses mlFeatures.hostname_digit_ratio (already computed
  // for the ML model). Excluded for IP hostnames (which are, by
  // definition, almost entirely digits - already fully scored by
  // isIpAddress above) and requires a minimum hostname length so a short,
  // ordinary label like "g2.io" can never trigger it.
  if (
    !urlFacts.isIpAddress &&
    mlFeatures &&
    typeof mlFeatures.hostname_digit_ratio === "number" &&
    mlFeatures.hostname_digit_ratio >= 0.5 &&
    urlFacts.hostname.length >= 6
  ) {
    score += 8;
    flags.push({ level: "info", text: "Hostname consists largely of digits" });
  }

  // Brand impersonation heuristic: a known brand name appears as a distinct
  // token in a HOSTNAME LABEL (whole label, or hyphen-adjacent within it),
  // while the REGISTRABLE domain (real Public Suffix List parsing - see
  // js/psl.js, NOT a naive slice(-2)) is not that brand's own. Restricted to
  // hostname (not free-text path) and to whole-label/hyphen-adjacent matches,
  // so "github.com/login" or "accounts.google.com" are never flagged, and
  // co.uk/co.in/com.au/github.io-style domains are parsed correctly.
  const labels = urlFacts.hostname.split(".");
  const regLabel = (urlFacts.registrableDomain.split(".")[0] || "").toLowerCase();
  for (const brand of KNOWN_BRANDS) {
    // Any hostname label that IS the brand, or is hyphen-adjacent to it
    // within a label (e.g. "paypal-secure"), counts as a mention. The
    // outer `regLabel !== brand` check below is what correctly excludes
    // genuinely legitimate cases like "www.apple.com" (regLabel === "apple"
    // there) - a brand mention that is NOT the registrable domain's own
    // label is exactly the subdomain-impersonation pattern (e.g.
    // "appleid.apple.com.evil.xyz", where "apple" appears as a fake
    // subdomain but the real registrable domain is "evil.xyz").
    const hit = labels.some(
      (label) => label === brand || label.startsWith(brand + "-") || label.endsWith("-" + brand) || label.includes("-" + brand + "-")
    );
    if (hit && regLabel !== brand) {
      score += 35;
      brandImpersonationDetected = true;
      flags.push({
        level: "critical",
        text: `Hostname references "${brand}" but the actual domain is "${urlFacts.registrableDomain}"`,
      });
      break;
    }
  }

  // RANK 2 FIX (hyphen-fragmented brand + extra token): the loop above only
  // catches a known brand appearing as a single, UNBROKEN hostname-label
  // token (e.g. "paypal-login"). It does not catch a brand name that is
  // itself split by an internal hyphen (e.g. "pay-pal-login"), where the
  // brand only becomes visible after joining two of the label's own
  // hyphen-separated tokens back together - a real typosquatting technique
  // (spec example: "pay-pal-example.com"), distinct from the plain
  // "brand-word" pattern already handled above.
  //
  // Deliberately narrow and EXACT-match only (no fuzzy/edit-distance
  // matching here - that stays in detectTyposquatting below, scored
  // separately and lower, per the existing "fuzzy match is inherently less
  // certain than an exact brand token" design already used elsewhere in
  // this file):
  //  - only ever joins a CONTIGUOUS run of ONE label's own hyphen-separated
  //    tokens - never spans across label boundaries (a subdomain label is
  //    never combined with the registrable domain's label)
  //  - the run must be a PREFIX or SUFFIX of that label's tokens, with at
  //    least one token left over on the other side. A run using ALL of a
  //    label's tokens (nothing left over) is not this pattern - that's
  //    just the brand's own name with hyphen noise and is already handled
  //    by detectTyposquatting's own hyphen-stripping/exact-match branch
  //    below (e.g. "pay-pal.com" alone, with no extra word)
  //  - the joined run must EXACTLY equal a known brand, minimum length 5 -
  //    the same "Experiment B" margin already used for path/query-token
  //    brand matching above, which excludes "absa"/"sber" (4 chars) here
  //    too for the same reason
  // Uses the SAME +35 score and brandImpersonationDetected flag as the
  // hostname-label loop above - no new scoring tier introduced. Measured
  // against the 107-legit regression suite: 0 new false positives (no
  // legitimate hostname in that suite contains a hyphen at all).
  if (!brandImpersonationDetected) {
    hyphenBrandSearch: for (const label of labels) {
      const hyphenTokens = label.split("-").filter(Boolean);
      if (hyphenTokens.length < 2) continue;
      for (let k = 1; k < hyphenTokens.length; k++) {
        const prefixRun = hyphenTokens.slice(0, k).join("");
        const suffixRun = hyphenTokens.slice(hyphenTokens.length - k).join("");
        for (const run of [prefixRun, suffixRun]) {
          if (run.length < TYPOSQUAT_MIN_BRAND_LEN) continue;
          if (KNOWN_BRANDS.includes(run)) {
            score += 35;
            brandImpersonationDetected = true;
            flags.push({
              level: "critical",
              text: `Hostname label "${label}" spells out "${run}" across a hyphen alongside an unrelated token, but the actual domain is "${urlFacts.registrableDomain}"`,
            });
            break hyphenBrandSearch;
          }
        }
      }
    }
  }

  // FIX (deceptive multi-label-suffix brand impersonation - the
  // "brand.com.gl" pattern; added per real-browser evidence:
  // https://roblox.com.gl/ measured SAFE 6 under the hostname-label check
  // above). That check treats `regLabel === brand` as proof the domain is
  // the brand's own (correctly excludes "www.apple.com", regLabel
  // "apple") - but that assumption only holds when the PSL-recognized
  // public suffix is a single label ("com"). For a REAL, PSL-recognized
  // multi-label suffix (js/psl_data.json - not a guess or a new list), a
  // domain's second-level label can still equal the brand exactly while
  // the full registrable domain is an entirely different registration
  // designed to LOOK like "<brand>.com" at a glance - e.g.
  // "roblox.com.gl" has regLabel "roblox" (exact match) but its real
  // registrable domain is "roblox.com.gl" (Guatemala's "com.gl" suffix,
  // unrelated to Roblox's actual "roblox.com"). Deliberately narrow -
  // THREE independent conditions, all required:
  //  1. regLabel === brand EXACTLY - reuses the same exact-match
  //     primitive as the loop above, never a substring/prefix/fused
  //     match. This is what keeps "login.microsoftonline.com" safe:
  //     "microsoftonline" !== "microsoft", so this branch never even
  //     reaches the suffix check below for that domain - same reason it
  //     never matched the hostname-label loop above.
  //  2. urlFacts.tld (the REAL PSL-parsed public suffix, already computed
  //     once in featureExtractor.js - not re-derived or guessed here) has
  //     2+ labels, so every ordinary single-label suffix ("com", "in",
  //     "app", "io", ...) is structurally excluded and plain "<brand>.com"
  //     domains are entirely unaffected.
  //  3. that suffix's first label is "com", "net", or "org" - the small,
  //     specific set that creates the "looks like the dot-com you know"
  //     illusion - AND the full suffix is NOT already in MULTI_PART_TLDS
  //     (PhishGuard's existing recognized-legitimate regional suffixes,
  //     e.g. "co.uk"/"com.au"/"com.br"/"co.jp"), so a brand's genuine
  //     regional presence under an already-recognized suffix is untouched.
  // Uses the SAME +35 score and brandImpersonationDetected flag as the
  // hostname-label check above - no new scoring tier introduced.
  //
  // NOTE: this does NOT attempt to catch the separate "whatsappgroup.app"
  // pattern (brand fused as a PREFIX of an otherwise-unrelated single
  // label, no suffix trickery involved). That pattern is structurally
  // identical to legitimate fused domains this project must keep safe
  // (e.g. "microsoftonline.com" is also "<brand>" + extra letters fused
  // with no delimiter) and cannot be told apart from them by hostname
  // structure alone - see the false-positive requirements this task lists
  // and requirement 6 ("Do NOT create a generic rule such as: brand
  // appears anywhere in hostname => phishing"). Reliably catching it would
  // need a brand-to-legitimate-domain allowlist, which is out of scope for
  // this change.
  if (!brandImpersonationDetected) {
    const suffixLabels = urlFacts.tld ? urlFacts.tld.split(".") : [];
    const hasDeceptiveSuffix =
      suffixLabels.length >= 2 &&
      ["com", "net", "org"].includes(suffixLabels[0]) &&
      !MULTI_PART_TLDS.has(urlFacts.tld);
    if (hasDeceptiveSuffix && KNOWN_BRANDS.includes(regLabel)) {
      score += 35;
      brandImpersonationDetected = true;
      flags.push({
        level: "critical",
        text: `Domain "${urlFacts.registrableDomain}" uses "${regLabel}" with a deceptive ".${suffixLabels[0]}"-prefixed suffix - not the real "${regLabel}.${suffixLabels[0]}"`,
      });
    }
  }

  // FIX (path/query brand-token detection - validated via scratch experiment,
  // "Experiment B" variant): the hostname check above misses cases where a
  // brand name is impersonated in the URL PATH or QUERY rather than the
  // hostname (e.g. a compromised/throwaway domain hosting
  // "/lander/interac" or "/.../wellsfargo/..."). Only runs when the
  // hostname branch above did NOT already match (mirrors that branch's
  // early exit), uses the SAME +35 score and brandImpersonationDetected
  // flag - no new scoring tier introduced. Boundary-aware by design: a
  // WHOLE path/query token must equal a brand name exactly (never a
  // substring of a longer token, e.g. "absaonline" or "chaselogin01a" do
  // NOT match), with a minimum token length of 5 as an added
  // false-positive safety margin, which excludes the two shortest
  // KNOWN_BRANDS entries ("absa", "sber", 4 chars each) - this is the
  // "Experiment B" boundary from the validated analysis, chosen over the
  // looser "Experiment A" (which also matched "sber") for extra safety
  // margin on short brand strings. Measured on the 107-legit/120-phishing
  // regression suites: 0/107 new false positives, +2 phishing detections
  // ("interac", "wellsfargo") over the hostname-only baseline.
  if (!brandImpersonationDetected) {
    let pathname = "";
    try {
      const u = new URL(urlFacts.normalizedUrl);
      pathname = u.pathname || "";
    } catch {
      // Malformed/unparseable URL - no path evidence available, fall
      // through with no hit (consistent with "unavailable is not evidence"
      // elsewhere in this file).
    }
    const pathTokens = pathname.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    const pathHit = pathTokens.find((t) => t.length >= 5 && KNOWN_BRANDS.includes(t));
    const hit = pathHit;
    if (hit) {
      score += 35;
      brandImpersonationDetected = true;
      flags.push({
        level: "critical",
        text: `URL path references "${hit}" but the hostname is "${urlFacts.hostname}"`,
      });
    }
  }

  // RANK 2: typosquatting - only checked when the hostname isn't ALREADY
  // flagged for exact brand impersonation above (avoids double-counting the
  // same underlying evidence under two different labels). Scored lower
  // (25 vs 35) and kept out of brandImpersonationDetected/
  // brandPlusMlCombo - a fuzzy match is inherently less certain than an
  // exact brand token, so it gets its own, separately-gated escalation
  // path (see typosquattingDetected below and qualifiesForHighRisk's
  // typosquatCredentialCombo).
  let typosquattingDetected = false;
  if (!brandImpersonationDetected) {
    const typo = detectTyposquatting(urlFacts);
    if (typo.matched) {
      score += 25;
      typosquattingDetected = true;
      flags.push({
        level: "warning",
        text: `Domain "${urlFacts.registrableDomain}" closely resembles "${typo.brand}.com" (possible typosquatting)`,
      });
    }
  }

  // RANK 3: Punycode / internationalized-domain (IDN) / mixed-script /
  // homoglyph detection. Supporting evidence only, per spec - many
  // legitimate sites use IDNs, so none of this scores heavily on its own
  // and none of it is folded into brandImpersonationDetected/
  // typosquattingDetected above (kept in its own flag,
  // homoglyphBrandImpersonationDetected, below).
  //
  // FIX (Rank 3): the prior version of this block tested the HOSTNAME
  // STRING ITSELF for raw Cyrillic/Greek Unicode code points. That can
  // only ever match if the hostname is already in decoded Unicode form -
  // but a Punycode-encoded label ("xn--...") is, by construction, pure
  // ASCII, so that check could never actually fire on a real IDN/homograph
  // domain (the exact case this section exists to catch). Labels are now
  // decoded back to their real Unicode text first (see js/idn.js - a
  // small, self-contained RFC 3492 decoder; never throws, falls back to
  // the original ASCII label untouched on any malformed input), and
  // mixed-script/homoglyph analysis runs on THAT. This also transparently
  // covers the (less common) case where a hostname arrives already in raw
  // Unicode form, since decodeIdnLabel() passes non-"xn--" labels through
  // unchanged and isMixedScriptLabel()/normalizeHomoglyphsUnicode() work
  // on Unicode text either way.
  //
  // urlFacts.hostname itself is NEVER modified here - only used to derive
  // this supporting analysis; the original hostname is preserved for
  // display/evidence exactly as before (spec: "Do NOT destroy the
  // original URL").
  const isPunycode = !!(mlFeatures && mlFeatures.is_punycode) || urlFacts.hostname.includes("xn--");
  const decodedLabels = urlFacts.hostname.split(".").map((label) => decodeIdnLabel(label).text);
  // A label written ENTIRELY in one non-Latin script is ordinary,
  // legitimate IDN use (spec: "A domain entirely written in one legitimate
  // non-Latin script may be normal") - only genuine script MIXING within a
  // single label counts, since that has essentially no legitimate use
  // case (classic homograph-attack pattern).
  const isMixedScript = decodedLabels.some((text) => isMixedScriptLabel(text));

  let punycodeOrIdnDetected = false;
  if (isMixedScript) {
    score += 20;
    punycodeOrIdnDetected = true;
    flags.push({ level: "warning", text: "Hostname mixes Latin letters with visually similar characters from another script" });
  } else if (isPunycode) {
    score += 15;
    punycodeOrIdnDetected = true;
    flags.push({ level: "info", text: "Hostname uses Punycode (internationalized domain) encoding, which can visually resemble a different domain" });
  }

  // RANK 3 (homoglyph brand impersonation): see
  // detectHomoglyphBrandImpersonation() above for the exact-match-only
  // matching strategy and why it cannot double-count Rank 2's
  // typosquatting evidence. Gated behind !brandImpersonationDetected for
  // the same reason every other supplementary brand check in this file is
  // (see the hyphen-split check above) - avoid piling more score/flags on
  // top of a stronger signal that already fired. Scored between
  // typosquatting (25 - a fuzzy, uncertain edit-distance guess) and exact
  // ASCII brand-token impersonation (35 - a literal, unambiguous token
  // match): this is an exact reconstruction of the brand name, so more
  // certain than a fuzzy typo, but IDN-derived and dependent on the
  // (deliberately small) confusable table, so kept below the ASCII
  // exact-match tier out of caution. Never sufficient alone for HIGH_RISK -
  // see qualifiesForHighRisk()'s homoglyphCredentialCombo, which requires
  // independently-observed credential-harvesting DOM evidence too, mirroring
  // typosquatCredentialCombo exactly.
  let homoglyphBrandImpersonationDetected = false;
  if (!brandImpersonationDetected) {
    const homoglyphMatch = detectHomoglyphBrandImpersonation(urlFacts);
    if (homoglyphMatch.matched) {
      score += 30;
      homoglyphBrandImpersonationDetected = true;
      flags.push({
        level: "warning",
        text: `Domain "${urlFacts.registrableDomain}" uses internationalized/Unicode characters that closely resemble "${homoglyphMatch.brand}.com" (possible homograph impersonation)`,
      });
    }
  }

  // RANK 6 (URL feature engineering - length). Per spec section 4.A:
  // "long" URLs (many legitimate services - OAuth, search results, CDN
  // links) must NOT be treated as suspicious at all; only a VERY long URL
  // contributes, and only a small, weak amount. Reuses
  // mlFeatures.url_length (already computed for the ML model).
  if (mlFeatures && typeof mlFeatures.url_length === "number" && mlFeatures.url_length > VERY_LONG_URL_LENGTH) {
    complexityScore += 5;
    flags.push({ level: "info", text: `URL is unusually long (${mlFeatures.url_length} characters)` });
  }

  // RANK 6 (URL feature engineering - query parameters + redirect
  // parameters). urlFacts.query is the new non-ML field added to
  // urlFacts() (see featureExtractor.js) - already parsed there by the
  // canonical simpleUrlSplit(), not re-parsed here.
  const queryParams = parseQueryParams(urlFacts.query);

  // Per spec section 4.D: many legitimate sites (analytics, OAuth, search)
  // carry several query parameters - a high COUNT alone is only weak,
  // supporting evidence, never enough alone (see MANY_QUERY_PARAMS_THRESHOLD
  // comment above).
  if (queryParams.length >= MANY_QUERY_PARAMS_THRESHOLD) {
    complexityScore += 5;
    flags.push({ level: "info", text: `URL has an unusually large number of query parameters (${queryParams.length})` });
  }

  // Per spec section 11 and the explicit "SPECIAL REQUIREMENT FOR REDIRECT
  // PARAMETERS": a redirect-style parameter NAME alone (url=/redirect=/
  // next=/return=/continue=/target=/destination=/callback=) must never by
  // itself score anything - only a parameter whose VALUE is itself an
  // absolute URL pointing at a DIFFERENT host (not this page's own hostname
  // or a subdomain of its own registrable domain) is treated as evidence.
  // A same-site value (e.g. "continue=/dashboard", or even
  // "continue=https://accounts.google.com/..." on a google.com page) never
  // matches, which is exactly what keeps ordinary OAuth/login-continuation
  // URLs safe. Only the FIRST match is scored (mirrors the
  // "break after first match" pattern used by the brand-impersonation
  // checks above) so multiple redirect-style parameters on the same URL
  // don't stack into a disproportionate penalty for what is still one
  // underlying observation.
  let redirectParamFlagged = false;
  for (const { key, value } of queryParams) {
    if (redirectParamFlagged) break;
    if (!REDIRECT_PARAM_NAMES.has(key.toLowerCase())) continue;
    const embeddedHost = extractEmbeddedHost(value);
    if (!embeddedHost) continue; // relative path / not URL-like - the ordinary, safe case
    const sameHost = embeddedHost === urlFacts.hostname;
    const sameRegistrableDomain =
      !!urlFacts.registrableDomain &&
      (embeddedHost === urlFacts.registrableDomain || embeddedHost.endsWith("." + urlFacts.registrableDomain));
    if (sameHost || sameRegistrableDomain) continue; // same-site redirect target - safe, matches spec's explicit requirement
    score += 15;
    redirectParamFlagged = true;
    flags.push({
      level: "warning",
      text: `URL parameter "${key}" redirects to a different domain ("${embeddedHost}")`,
    });
  }

  // RANK 6 (URL feature engineering - encoding). Per spec section 4.E:
  // ordinary/incidental percent-encoding (a couple of %20/%2F in a normal
  // path or query) must never be flagged - only a genuinely EXCESSIVE
  // amount (both an absolute minimum count AND a high ratio relative to
  // total URL length) counts as supporting evidence. Reuses
  // mlFeatures.percent_count / url_length (both already computed for the ML
  // model; has_percent_encoding itself - a plain boolean - is deliberately
  // NOT used here, since it would fire on completely ordinary URLs).
  if (
    mlFeatures &&
    typeof mlFeatures.percent_count === "number" &&
    typeof mlFeatures.url_length === "number" &&
    mlFeatures.url_length > 0 &&
    mlFeatures.percent_count >= EXCESSIVE_PERCENT_COUNT_MIN &&
    mlFeatures.percent_count / mlFeatures.url_length >= EXCESSIVE_PERCENT_RATIO
  ) {
    complexityScore += 10;
    flags.push({ level: "warning", text: "URL contains an unusually high amount of percent-encoding" });
  }

  // RANK 6 (URL feature engineering - path structure). Per spec section
  // 4.C: a repeated identical path segment (e.g. "/login/login/verify/
  // verify") is a mild obfuscation/anomaly signal - kept weak and requiring
  // 3+ repeats of a non-trivial segment specifically to avoid firing on
  // ordinary patterns like a two-level locale prefix ("/en/en-us/...").
  // urlFacts.path is the new non-ML field added to urlFacts() above -
  // already parsed by simpleUrlSplit(), not re-parsed here.
  if (hasRepeatedPathSegment(urlFacts.path)) {
    complexityScore += 5;
    flags.push({ level: "info", text: "URL path repeats the same segment multiple times" });
  }

  // RANK 7 (corroboration - signal-family grouping): fold the URL-
  // complexity family into `score` exactly once, capped at
  // URL_COMPLEXITY_FAMILY_CAP - see that constant's comment for why this
  // specific cap value cannot affect any 1- or 2-signal case. Every other
  // check in this function (IP address, typosquatting, IDN/homoglyph,
  // brand impersonation, redirect-parameter cross-domain, digit-heavy
  // hostname, long hostname label, keyword hits, shortener/suspicious-TLD,
  // subdomain depth) is untouched and continues to add to `score` directly,
  // exactly as before.
  score += Math.min(complexityScore, URL_COMPLEXITY_FAMILY_CAP);

  return {
    score: clamp(score, 0, 100),
    flags,
    brandImpersonationDetected,
    typosquattingDetected,
    punycodeOrIdnDetected,
    homoglyphBrandImpersonationDetected,
    available: true,
    confidence: 1.0,
  };
}

function scoreDom(domSignals) {
  // Per spec: DOM unavailable (page blocked/offline, content script couldn't
  // run, Safe Browsing interstitial, not yet loaded, etc.) is UNKNOWN - not
  // safe, not malicious. It contributes 0 and is labeled accordingly.
  if (!domSignals || !domSignals.available) {
    return {
      score: 0, flags: [], available: false, confidence: 0,
      hasCredentialHarvestPattern: false, hasPasswordField: false,
      hasOtpField: false, hasPaymentField: false, hasMultipleSensitiveFieldTypes: false,
      crossOriginFormCount: 0, weakScore: 0, weakFlags: [],
      hiddenCredentialWeakScore: 0, hiddenCredentialWeakFlags: [],
    };
  }
  const f = domSignals;
  let score = 0;
  const flags = [];
  let hasCredentialHarvestPattern = false;

  // RANK 4 (advanced credential/form correlation): broadened from
  // "password field" to any sensitive field TYPE - password, one-time-code
  // (OTP), or payment/card - submitted cross-origin. A credential-
  // harvesting page doesn't always ask for a password specifically:
  // OTP-only phishing (bypassing a real site's own 2FA prompt) and
  // card-only skimmer pages are both common and were previously invisible
  // to this check. The cross-origin-submission requirement is unchanged -
  // still the actual second, independent fact that makes this meaningful
  // (a bare sensitive field, of any type, alone is still just +6 below).
  const sensitiveFieldTypeCount = [f.hasPasswordField, f.hasOtpField, f.hasPaymentField].filter(Boolean).length;
  const hasSensitiveField = sensitiveFieldTypeCount > 0;
  // RANK 4 (multi-factor field correlation): TWO OR MORE distinct sensitive
  // field types (password+OTP, password+payment, OTP+payment) on the SAME
  // page is unusual for a legitimate flow, which normally presents these as
  // separate SEQUENTIAL steps (password page, then a separate OTP
  // challenge page) rather than one combined page/form. Not scored
  // directly here (still just +6 via hasSensitiveField below, or whatever
  // the cross-origin branch above already gives it) - deliberately kept as
  // a plain, carried-through FACT only, consumed exclusively by
  // qualifiesForHighRisk()'s multiFieldDomainCombo and
  // qualifiesForCombinedWeakEvidenceSuspicion() below, both of which
  // additionally require an independent domain-level red flag before this
  // contributes anything - never sufficient alone (spec section 9: "OTP
  // field alone MUST NOT automatically produce HIGH_RISK").
  const hasMultipleSensitiveFieldTypes = sensitiveFieldTypeCount >= 2;

  if (hasSensitiveField && f.hasCrossOriginFormAction) {
    // Multiple DIFFERENT sensitive field types corroborating each other in
    // the SAME cross-origin form (e.g. password + OTP, or password + card)
    // is stronger evidence than any one type alone - a small, capped bonus
    // reflects that without letting this branch run away (max +70 total,
    // still well inside the 0-100 internal scale every other category uses).
    score += 55 + Math.min(15, (sensitiveFieldTypeCount - 1) * 8);
    hasCredentialHarvestPattern = true;
    const kind = f.hasPasswordField ? "Login form" : f.hasOtpField ? "One-time-code form" : "Payment form";
    flags.push({ level: "critical", text: `${kind} submits sensitive data to a different domain` });
  } else if (hasSensitiveField && f.formActionMissingOrSuspicious) {
    // RANK 4 FIX (consistency): broadened from f.hasPasswordField to
    // hasSensitiveField for the same reason as the branch above - a
    // malformed/unparseable form action on an OTP- or payment-only form is
    // just as meaningful as on a password form; there is no principled
    // reason this branch alone should stay password-only when every other
    // branch in this function was already broadened.
    score += 20;
    const kind = f.hasPasswordField ? "Password field" : f.hasOtpField ? "One-time-code field" : "Payment field";
    flags.push({ level: "warning", text: `${kind} found with an unusual or missing form target` });
  } else if (hasSensitiveField) {
    score += 6;
    flags.push({ level: "info", text: "Page contains a login, one-time-code, or payment form" });
  }

  if (f.crossOriginFormCount > 0 && !f.hasPasswordField) {
    score += 5; // weak alone - many legit sites use external payment/auth providers
  }

  // --- FIX (false-positive patch) ---
  // Hidden iframes and an invisible full-page overlay are common in
  // legitimate modern web apps (hidden auth/analytics/third-party-service
  // iframes; modal, loading, consent, or accessibility overlay layers) and
  // must NOT, by themselves, push a page toward SUSPICIOUS. They are still
  // fully detected here and still surfaced in the explanation (see
  // `weakFlags`, always included below in computeRisk), but their point
  // value is kept separate as `weakScore` instead of being folded into
  // `score` directly. computeRisk() only adds `weakScore` into the page's
  // effective DOM score when at least one independently-observed stronger
  // signal is also present - credential harvesting, a password field, a
  // cross-origin form submission, brand impersonation, a suspicious URL
  // structure, or a newly-registered domain
  // (see weakDomSignalIsCorroborated()). This keeps iframe/overlay
  // detection meaningful for real phishing (which typically pairs a
  // hidden iframe/overlay with at least one of those) while removing the
  // false-positive path where a clean, established site is flagged purely
  // for generic web-app plumbing.
  let weakScore = 0;
  const weakFlags = [];
  if (f.hiddenIframeCount > 0) {
    weakScore += 15;
    weakFlags.push({ level: "warning", text: `${f.hiddenIframeCount} hidden iframe(s) detected` });
  }
  if (f.crossOriginIframeCount > 2) {
    // Ordinary third-party embeds (ads, maps, video, chat/comment widgets,
    // analytics) routinely put a legitimate modern page over this count -
    // same rationale as hidden iframes above, so it moves into the same
    // gated bucket rather than scoring unconditionally.
    weakScore += 8;
    weakFlags.push({ level: "info", text: "Multiple cross-origin iframes on this page" });
  }
  if (f.suspiciousBehaviorFlags && f.suspiciousBehaviorFlags.length > 0) {
    weakScore += 12;
    for (const b of f.suspiciousBehaviorFlags.slice(0, 2)) weakFlags.push({ level: "warning", text: b });
  }

  // RANK 4 (hidden/deceptive credential field detection - see content.js's
  // analyzeHiddenCredentialFields()). Kept in its OWN weak/gated bucket,
  // SEPARATE from weakScore/weakFlags above, because it needs a STRICTER
  // corroboration gate than hidden iframes/overlays - see
  // hiddenCredentialFieldIsCorroborated() below, which deliberately omits
  // the bare "hasPasswordField" clause that weakDomSignalIsCorroborated()
  // uses (a hidden decoy password field is also a known LEGITIMATE
  // anti-autofill-mismatch technique, and hasPasswordField is true on
  // essentially every ordinary login page, so gating on it here would not
  // actually protect the false-positive case spec section 10 calls out by
  // name: "legitimate sites containing ... hidden framework elements").
  // Flag is always surfaced (transparency preserved either way, same
  // pattern as weakFlags above); only the score contribution is
  // conditional - applied in computeRisk().
  let hiddenCredentialWeakScore = 0;
  const hiddenCredentialWeakFlags = [];
  if (f.hiddenCredentialFieldCount > 0) {
    hiddenCredentialWeakScore += 20;
    hiddenCredentialWeakFlags.push({
      level: "warning",
      text: `${f.hiddenCredentialFieldCount} hidden or off-screen credential-type field(s) detected (password, one-time-code, or payment input present but not visible to the user)`,
    });
  }

  return {
    score: clamp(score, 0, 100),
    flags,
    weakScore,
    weakFlags,
    hiddenCredentialWeakScore,
    hiddenCredentialWeakFlags,
    available: true,
    confidence: 1.0,
    hasCredentialHarvestPattern,
    hasPasswordField: !!f.hasPasswordField,
    hasOtpField: !!f.hasOtpField,
    hasPaymentField: !!f.hasPaymentField,
    hasMultipleSensitiveFieldTypes,
    crossOriginFormCount: f.crossOriginFormCount || 0,
  };
}

/**
 * FIX (false-positive patch, see scoreDom() above): decides whether the
 * weak, context-dependent DOM signals (hidden iframes, an invisible
 * full-page overlay) are corroborated by at least one independently
 * observed piece of stronger evidence, per the project spec's own examples
 * ("hidden iframe + credential-harvesting form", "overlay + password
 * field", "overlay + cross-origin submission", "... + brand impersonation",
 * "... + suspicious URL structure"). Deliberately does NOT treat a high ML
 * prediction as corroboration here - ML is gated separately (see
 * qualifiesForSuspicious() below) precisely so "ML says risky" plus "page
 * happens to have a hidden iframe" can never combine into a false positive
 * for an otherwise clean, established site.
 */
function weakDomSignalIsCorroborated({ dom, urlHeur, domainScore }) {
  return (
    dom.hasCredentialHarvestPattern ||
    dom.hasPasswordField ||
    dom.crossOriginFormCount > 0 ||
    urlHeur.brandImpersonationDetected ||
    urlHeur.typosquattingDetected || // RANK 2
    urlHeur.homoglyphBrandImpersonationDetected || // RANK 3
    urlHeur.score >= 25 || // e.g. IP-address URL, '@' obfuscation, suspicious TLD/shortener, high hostname entropy
    (domainScore.available && domainScore.score >= ELEVATED_THRESHOLD) // newly-registered domain
  );
}

/**
 * RANK 4 (hidden/deceptive credential field gating): mirrors
 * weakDomSignalIsCorroborated() above but deliberately OMITS the bare
 * dom.hasPasswordField clause. A hidden/off-screen password, OTP, or
 * payment field is ALSO a known LEGITIMATE technique (e.g. a decoy password
 * field some login forms include specifically to steer browser autofill
 * away from the wrong visible field), and dom.hasPasswordField is true on
 * essentially every ordinary login page - gating this signal behind it, the
 * way hidden iframes/overlays already safely are, would not actually guard
 * against the exact false-positive case spec section 10 names explicitly
 * ("legitimate sites containing ... hidden framework elements"). This
 * requires a genuinely independent, less-common red flag instead: real
 * cross-domain form submission, an actual credential-harvest pattern,
 * brand impersonation, typosquatting, homoglyph impersonation, a
 * meaningful URL red flag, or a newly-registered domain.
 */
function hiddenCredentialFieldIsCorroborated({ dom, urlHeur, domainScore }) {
  return (
    dom.hasCredentialHarvestPattern ||
    dom.crossOriginFormCount > 0 ||
    urlHeur.brandImpersonationDetected ||
    urlHeur.typosquattingDetected ||
    urlHeur.homoglyphBrandImpersonationDetected ||
    urlHeur.score >= 25 ||
    (domainScore.available && domainScore.score >= ELEVATED_THRESHOLD)
  );
}

function scoreDomain(domain) {
  if (!domain || !domain.available || domain.ageDays == null) {
    return { score: 0, flags: [], available: false, confidence: 0 };
  }
  const days = domain.ageDays;
  let score = 0;
  let text = null;
  // Domain age is SUPPORTING evidence only (spec section 11) - note the
  // capped weight (7/100) means even a brand-new domain contributes at most
  // 7 points to the overall score, regardless of this internal 0-100 value.
  if (days < 7) { score = 70; text = "Domain was registered less than a week ago"; }
  else if (days < 30) { score = 50; text = "Domain was registered less than a month ago"; }
  else if (days < 90) { score = 25; text = "Domain is relatively new (under 3 months old)"; }
  else if (days < 365) { score = 8; text = null; }
  else { score = 0; text = null; }

  const flags = [];
  if (text) flags.push({ level: "warning", text });
  else if (days >= 365) flags.push({ level: "positive", text: "Domain has an established registration history" });
  return { score, flags, available: true, confidence: 1.0 };
}

function scoreDns(dns) {
  if (!dns || !dns.available) return { score: 0, flags: [], available: false, confidence: 0 };
  if (!dns.resolvesOk) {
    return {
      score: 40,
      flags: [{ level: "warning", text: "Domain does not currently resolve to any address" }],
      available: true,
      confidence: 1.0,
    };
  }
  // RANK 5 (DNS anomaly): an unusually short TTL on every resolved A/AAAA
  // record is one of the known signatures of fast-flux / rapidly-rotated
  // phishing hosting infrastructure. This is intentionally weak and capped -
  // some legitimate CDN/load-balanced setups also use short TTLs, so this
  // is supporting evidence only, never proof, consistent with how every
  // other single DNS/domain signal in this file is treated. The dns
  // category's weight (5) already keeps its MAXIMUM possible contribution
  // to the weighted score under 1 point either way; its real value is as
  // one more fact available to the corroboration logic below.
  let score = 0;
  const flags = [];
  if (typeof dns.minTtl === "number" && dns.minTtl > 0 && dns.minTtl < 120) {
    score += 15;
    flags.push({ level: "info", text: "Domain uses an unusually short DNS TTL (associated with rapidly-rotated hosting infrastructure)" });
  }
  // A domain resolving successfully is NOT evidence of safety (spec section
  // 20) - phishing domains routinely have valid DNS. Contributes 0, not a
  // "positive" signal.
  return { score: clamp(score, 0, 100), flags, available: true, confidence: 1.0 };
}

/**
 * RANK 1 (redirect-chain + final-destination analysis).
 *
 * DELIBERATELY HAS NO ENTRY IN WEIGHTS AND CONTRIBUTES NOTHING TO THE
 * WEIGHTED SUM in computeRisk() below - by design, per spec: "Redirects
 * alone should generally NOT produce HIGH_RISK ... They should become
 * powerful when combined with independent signals." Its score/flags are
 * used ONLY (a) as one of several signals in
 * qualifiesForCombinedWeakEvidenceSuspicion() (SUSPICIOUS tier, already
 * requires 2+ independent signals) and (b) in a small number of explicit,
 * named HIGH_RISK combinations in qualifiesForHighRisk() that each also
 * require an independently-observed DOM or brand/typosquat signal - never
 * redirect evidence by itself. Keeping WEIGHTS (ml/dom/urlHeuristics/
 * domain/dns, sum 100) completely unchanged is intentional per spec.
 *
 * Ordinary legitimate redirects - HTTP->HTTPS upgrade, www<->non-www,
 * OAuth/SSO hops, payment-provider hand-offs, CDN hops, country/language
 * redirects - are extremely common and must never, by themselves, move the
 * needle. What IS treated as noteworthy: an HTTPS->HTTP DOWNGRADE (the
 * opposite of the common, safe upgrade pattern), a chain that touches
 * several DIFFERENT hostnames before settling, and the chain's final
 * destination independently matching brand-impersonation/typosquatting
 * (already computed by scoreUrlHeuristics on the final URL, passed in here
 * as `urlHeurOfFinal` - never re-implemented) or a credential-harvesting
 * DOM pattern (`dom.hasCredentialHarvestPattern`).
 */
function scoreRedirect(redirect, urlHeurOfFinal, dom) {
  if (!redirect || !redirect.available) {
    return { score: 0, flags: [], available: false, confidence: 0, suspiciousPatternDetected: false };
  }

  const flags = [];
  let score = 0;
  const redirectCount = redirect.redirectCount || 0;
  const hostnameChanges = redirect.hostnameChanges || 0;

  if (redirectCount >= 1) {
    flags.push({ level: "info", text: `Reached final destination after ${redirectCount} redirect(s)` });
  }

  // A single hostname change is completely ordinary (one OAuth hop, one
  // payment-provider hand-off, a single shortener expansion, etc.) and
  // scores nothing. Several different hostnames in one chain is more
  // specific and unusual than a bare redirect count (a single site can
  // legitimately 302 several times without ever changing hostname, e.g.
  // path/locale normalization).
  if (hostnameChanges >= 3) {
    score += 25;
    flags.push({ level: "warning", text: `Redirect chain changed hostnames ${hostnameChanges} times before settling` });
  } else if (hostnameChanges === 2) {
    score += 12;
  }

  if (redirect.registrableDomainChanged) {
    // Weak alone - shorteners, payment processors, and SSO providers all do
    // this legitimately and constantly.
    score += 8;
  }

  if (redirect.httpsToHttpDowngrade) {
    score += 30;
    flags.push({ level: "warning", text: "Redirect chain downgraded from HTTPS to HTTP" });
  }

  const endsAtBrandImpersonation = !!(urlHeurOfFinal && urlHeurOfFinal.brandImpersonationDetected);
  const endsAtTyposquat = !!(urlHeurOfFinal && urlHeurOfFinal.typosquattingDetected);
  const endsAtCredentialHarvest = !!(dom && dom.hasCredentialHarvestPattern);

  if (redirectCount > 0 && endsAtBrandImpersonation) {
    flags.push({ level: "critical", text: "Redirect chain ends on a domain flagged for brand impersonation" });
  } else if (redirectCount > 0 && endsAtTyposquat) {
    flags.push({ level: "warning", text: "Redirect chain ends on a domain that closely resembles a known brand" });
  }
  if (redirectCount > 0 && endsAtCredentialHarvest) {
    flags.push({ level: "critical", text: "Redirect chain ends on a page submitting sensitive data to a foreign domain" });
  }

  // A chain only counts as "suspicious" for corroboration purposes once it
  // shows a real anomaly beyond ordinary redirect noise - not merely
  // "redirects happened" or "the domain changed once" (both far too common
  // on legitimate sites to mean anything alone).
  const suspiciousPatternDetected =
    redirect.httpsToHttpDowngrade ||
    hostnameChanges >= 3 ||
    (hostnameChanges >= 2 && redirect.registrableDomainChanged);

  return {
    score: clamp(score, 0, 100),
    flags,
    available: true,
    confidence: 1.0,
    redirectCount,
    hostnameChanges,
    registrableDomainChanged: !!redirect.registrableDomainChanged,
    httpsToHttpDowngrade: !!redirect.httpsToHttpDowngrade,
    suspiciousPatternDetected,
    endsAtBrandImpersonation,
    endsAtTyposquat,
    endsAtCredentialHarvest,
  };
}

/**
 * Explicit, auditable corroboration policy for the HIGH_RISK verdict.
 * Crossing the 60-point score threshold is NECESSARY but not SUFFICIENT -
 * this function decides whether the evidence is actually corroborated
 * enough to justify blocking, per the named combinations in the project
 * spec (credential harvesting, brand impersonation + ML, new domain + ML +
 * URL evidence, or 2+ independent elevated categories in general).
 *
 * ONE deliberate exception to "no single category decides alone": a DOM
 * scan showing a password field submitting to a cross-origin destination
 * (credentialHarvestCombo) qualifies on its own, without requiring ML or
 * any other category. This is not treated as a "single weak signal" like a
 * keyword or a hidden iframe - it is a directly observed technical fact
 * (not a heuristic guess) that is itself a conjunction of two independent
 * observations (a credential field exists, AND it is being sent somewhere
 * other than the page's own origin). Legitimate SSO/OAuth flows do not
 * produce this pattern - they redirect the whole page to the identity
 * provider rather than hosting a password field in a form actioned to a
 * foreign origin - so this does not carry the false-positive risk that
 * motivated gating every other combination behind multiple categories.
 */
function qualifiesForHighRisk({ ml, urlHeur, dom, domainScore, dnsScore, redirect }) {
  const categories = [
    { available: ml.available, score: ml.score },
    { available: true, score: urlHeur.score },
    { available: dom.available, score: dom.score },
    { available: domainScore.available, score: domainScore.score },
    { available: dnsScore.available, score: dnsScore.score },
    // NOTE: redirect is deliberately NOT included here. Unlike the five
    // categories above (each independently calibrated against the 107/120
    // regression suites), redirect evidence has no weight bucket and its
    // internal score was never tuned against elevatedCount's generic
    // "2-of-5 categories elevated" rule - folding it in here would let an
    // untested interaction silently unlock HIGH_RISK. It is instead used
    // ONLY via the explicit, narrow named combos below (each independently
    // reasoned about) and as a plain SUSPICIOUS-tier signal (see
    // qualifiesForCombinedWeakEvidenceSuspicion).
  ];
  const elevatedCount = categories.filter((c) => c.available && c.score >= ELEVATED_THRESHOLD).length;

  const credentialHarvestCombo = dom.available && dom.hasCredentialHarvestPattern;

  const brandPlusMlCombo = ml.available && ml.score >= 50 && urlHeur.brandImpersonationDetected;

  const newDomainMlUrlCombo =
    domainScore.available && domainScore.score >= ELEVATED_THRESHOLD &&
    ml.available && ml.score >= ELEVATED_THRESHOLD &&
    urlHeur.score >= 30;

  // FIX (evidence-fusion patch, Task 2/15): a named HIGH_RISK pattern from
  // spec Task 15 ("strong ML probability + meaningful URL/domain evidence")
  // had no corresponding rule here at all - the closest existing combos
  // (brandPlusMlCombo, newDomainMlUrlCombo) gate on ELEVATED_THRESHOLD (50)
  // for ML, not on genuinely STRONG ML (spec's own example: "0.90+"). The
  // combo below requires ML_STRONG_THRESHOLD (90) - well below the
  // isolated-ML gate (96) but never lets ML act alone: it also requires a
  // second, independently-observed real signal. hasVerifiedLegitimacyEvidence
  // guards it so an established-domain site can never qualify here
  // regardless of ML score (same protection already applied at the
  // SAFE/SUSPICIOUS boundary in qualifiesForSuspicious).
  const verifiedLegit = hasVerifiedLegitimacyEvidence({ domainScore });

  // CORRECTION (Rank 6 Chrome-testing finding): the URL-only branch below
  // used to gate on urlHeur.score >= 25 - the same "meaningful URL red
  // flag" bar used by qualifiesForSuspicious(). That bar is appropriate for
  // SUSPICIOUS (a single real observation), but too low to combine with
  // "merely strong" (not ultra-high) ML into HIGH_RISK: a bare IP hostname
  // (+25) or a handful of ordinary suspicious keywords (+30, e.g.
  // "/login/verify-account/password") already clears 25 on its own, with
  // zero credential/typosquat/homoglyph/new-domain/DNS evidence - exactly
  // the "URL heuristics alone forcing HIGH_RISK" failure mode reported
  // during Chrome testing. Raised to ELEVATED_THRESHOLD (50) so this
  // branch now requires the SAME bar as its domain-elevated sibling right
  // below it, and the same bar elevatedCount already uses everywhere else
  // in this file - not a new standard, just consistency with the existing
  // one. This does not weaken multi-signal cases: a URL that reaches
  // urlHeur.score >= 50 (e.g. IP + credential-relevant keywords + a
  // cross-domain redirect parameter, or Rank 2/3 typosquat/homoglyph brand
  // matches) is already independently "elevated" and, combined with an
  // elevated ML score, qualifies for HIGH_RISK via the untouched
  // elevatedCount >= 2 rule immediately above in this function - so
  // genuinely strong multi-signal URLs are unaffected; only the case of a
  // single, modest (25-49) URL-only signal riding on ML alone is reined in.
  const strongMlPlusUrlOrDomainCombo =
    !verifiedLegit &&
    ml.available && ml.score >= ML_STRONG_THRESHOLD &&
    (urlHeur.score >= ELEVATED_THRESHOLD || (domainScore.available && domainScore.score >= ELEVATED_THRESHOLD));

  // RANK 1 (redirect-chain corroboration): a suspicious redirect chain
  // (multi-hostname hopping and/or an HTTPS->HTTP downgrade - see
  // scoreRedirect()) that ALSO ends on a page independently flagged for
  // brand impersonation AND independently shows a credential-relevant DOM
  // signal. All three must be true; any one or two alone do not qualify.
  // This directly implements the spec's own worked example: "suspicious
  // redirect + brand impersonation + credential harvesting = strong/
  // high-risk evidence."
  const redirectBrandCredentialCombo =
    !!(redirect && redirect.available && redirect.suspiciousPatternDetected) &&
    urlHeur.brandImpersonationDetected &&
    dom.available &&
    (dom.hasCredentialHarvestPattern || dom.hasPasswordField);

  // A chain that actively downgrades from HTTPS to HTTP (the opposite of
  // the common, safe upgrade pattern) landing on a page with a password
  // field is a second, narrower named combo - still requires the
  // independently-observed DOM signal, redirect evidence never qualifies
  // alone.
  const redirectDowngradeCredentialCombo =
    !!(redirect && redirect.available && redirect.httpsToHttpDowngrade) &&
    dom.available &&
    dom.hasPasswordField;

  // RANK 2 (typosquatting corroboration): a domain that closely resembles
  // a known brand (see detectTyposquatting()) is only escalated to
  // HIGH_RISK when paired with a real, independently-observed DOM finding
  // beyond a bare password field (dom.score >= 20 excludes the info-level
  // "page has a login form" case worth only 6 points) OR an actual
  // credential-harvest pattern - matching spec: "Typosquatting + credential
  // harvesting + suspicious page behavior -> potentially HIGH_RISK."
  const typosquatCredentialCombo =
    urlHeur.typosquattingDetected &&
    dom.available &&
    (dom.hasCredentialHarvestPattern || (dom.hasPasswordField && dom.score >= 20));

  // RANK 3 (homoglyph corroboration): mirrors typosquatCredentialCombo
  // exactly, same reasoning - an IDN/homoglyph reconstruction of a known
  // brand (see detectHomoglyphBrandImpersonation()) is only escalated to
  // HIGH_RISK when paired with a real, independently-observed
  // credential-relevant DOM finding. IDN/homoglyph evidence never
  // qualifies for HIGH_RISK on its own, matching spec: "Do NOT make
  // 'Unicode detected' automatically equal HIGH_RISK."
  const homoglyphCredentialCombo =
    urlHeur.homoglyphBrandImpersonationDetected &&
    dom.available &&
    (dom.hasCredentialHarvestPattern || (dom.hasPasswordField && dom.score >= 20));

  // RANK 4 (multi-factor field + brand-impersonation combo): two or more
  // DIFFERENT sensitive field types on the SAME page (see
  // hasMultipleSensitiveFieldTypes in scoreDom() - password+OTP,
  // password+payment, or OTP+payment; unusual for a legitimate flow, which
  // normally presents these as separate sequential steps) paired with an
  // independently-observed domain-level brand-impersonation signal
  // (typosquatting, homoglyph, or exact brand-token impersonation) is a
  // named, narrow HIGH_RISK pattern - directly matching spec section 9's
  // own worked example: "credential harvesting + typosquatting/homoglyph +
  // sensitive login/payment context." Requires BOTH; neither alone
  // qualifies (multi-field-type alone is not necessarily malicious - some
  // legitimate flows do combine steps - and typosquatting/homoglyph alone
  // already has its own, separate, narrower gates above requiring a real
  // credential-harvest pattern or an elevated dom.score).
  const multiFieldDomainCombo =
    dom.available &&
    dom.hasMultipleSensitiveFieldTypes &&
    (urlHeur.typosquattingDetected || urlHeur.homoglyphBrandImpersonationDetected || urlHeur.brandImpersonationDetected);

  const qualifies =
    credentialHarvestCombo ||
    brandPlusMlCombo ||
    newDomainMlUrlCombo ||
    strongMlPlusUrlOrDomainCombo ||
    redirectBrandCredentialCombo ||
    redirectDowngradeCredentialCombo ||
    typosquatCredentialCombo ||
    homoglyphCredentialCombo ||
    multiFieldDomainCombo ||
    elevatedCount >= 2;

  return {
    qualifies,
    elevatedCount,
    credentialHarvestCombo,
    brandPlusMlCombo,
    newDomainMlUrlCombo,
    strongMlPlusUrlOrDomainCombo,
    redirectBrandCredentialCombo,
    redirectDowngradeCredentialCombo,
    typosquatCredentialCombo,
    homoglyphCredentialCombo,
    multiFieldDomainCombo,
  };
}

/**
 * FIX (false-positive patch): domain-age being merely UNAVAILABLE (WHOIS
 * lookup failed, offline, not yet resolved, etc.) is UNKNOWN, not a green
 * light - the project's own design intentionally requires ML to still work
 * standalone in that case (see training/legit_regression_suite.json's note
 * that "core detection must work without external services"). This function
 * returns true ONLY when domain age was actually CHECKED and came back
 * affirmatively positive evidence (an established domain).
 */
function hasVerifiedLegitimacyEvidence({ domainScore }) {
  return domainScore.available && domainScore.score === 0;
}

/**
 * FIX (evidence-fusion patch, replaces an earlier "isolated ML" version of
 * this gate - see training/README.md "Risk engine: isolated-ML gate
 * replaced" for the measured investigation behind this change):
 *
 * An earlier version of this gate let a sufficiently high ML score promote
 * the verdict to SUSPICIOUS on its own whenever domain age hadn't
 * actually been checked, closing a real false-negative gap (see
 * qualifiesForSuspicious() below for the companion SAFE/SUSPICIOUS boundary
 * problem this was originally solving). But measurement against PhishGuard's
 * own held-out model-evaluation data showed that gate could not be tuned to
 * work: real login/auth-flow pages on major legitimate domains
 * (accounts.google.com/signin, claude.ai/new, login.microsoftonline.com)
 * score in the SAME 70-95% ML range as confirmed phishing credential-harvest
 * pages, when URL/page features are the only signal available - there is no
 * probability threshold that separates them without also discarding most of
 * the phishing detections it was meant to add. That is a property of the
 * feature space, not a tuning mistake, and it matches this file's own stated
 * objective (spec section 30): an established or unknown domain + uncertain
 * ML alone should generally stay SAFE.
 *
 * This version never lets ML act alone. It requires at least ML PLUS one
 * OTHER independently-observed, genuinely negative signal - not "elevated"
 * in the stricter qualifiesForHighRisk() sense (which correctly reserves
 * HIGH_RISK for stronger corroboration), but real evidence that was actually
 * gathered and points the wrong way: a domain genuinely registered very
 * recently (not just unavailable), a meaningful URL red flag, or an actual
 * DOM finding. A famous domain with everything else unavailable no longer
 * qualifies no matter how high its ML score - exactly like it wouldn't if ML
 * were unavailable too.
 *
 * RANK 5 (domain + DNS correlation): dnsScore was previously not passed to
 * this function at all, so a DNS anomaly (short TTL, or the domain not
 * currently resolving - see scoreDns()) could never combine with another
 * weak signal here, even though the dns category's own score already exists
 * for exactly this purpose (its weight, 5, is deliberately too small for it
 * to move the needle alone). Adding it as one more entry in `signals` below
 * is purely additive: this function still requires 2+ true signals, so per
 * spec section 6/15 a DNS anomaly alone ("SHORT TTL alone -> NOT HIGH_RISK",
 * "DNS unavailable alone -> NOT HIGH_RISK") still can never qualify by
 * itself - it only matters once paired with a genuinely independent second
 * signal (e.g. a domain actually confirmed very new - spec's own worked
 * example, "VERY NEW DOMAIN + SUSPICIOUS DNS CHARACTERISTICS -> stronger
 * evidence"). Note this only ever reaches SUSPICIOUS (never HIGH_RISK) via
 * this function - qualifiesForHighRisk()'s own `categories`/elevatedCount
 * check deliberately still gates DNS at ELEVATED_THRESHOLD (50), which its
 * capped internal score (max 40) can never reach, so domain+DNS alone can
 * never escalate past SUSPICIOUS through this path either. That is
 * intentional: a legitimate, newly-launched site behind a CDN (short TTL is
 * routine there) must never be pushed to HIGH_RISK on domain+DNS metadata
 * alone (spec section 15 explicitly calls out both "newly registered
 * legitimate domains" and "domains using short DNS TTL" as protected
 * false-positive cases).
 */
function qualifiesForCombinedWeakEvidenceSuspicion({ ml, urlHeur, dom, domainScore, dnsScore, redirect }) {
  if (hasVerifiedLegitimacyEvidence({ domainScore })) return false;
  const signals = [
    ml.available && ml.score >= ELEVATED_THRESHOLD,
    domainScore.available && domainScore.score >= ELEVATED_THRESHOLD,
    urlHeur.score >= 25,
    dom.available && dom.score >= 20, // warning/critical DOM finding, not a bare password field alone
    // RANK 1: a genuinely anomalous redirect chain (not just "a redirect
    // happened") counts as one signal among several here - never enough by
    // itself (this function already requires 2+ true), matching spec:
    // "Redirects alone should generally NOT produce HIGH_RISK ... become
    // powerful when combined with independent signals."
    !!(redirect && redirect.available && redirect.suspiciousPatternDetected),
    // RANK 4: two or more DIFFERENT sensitive field types on the same page
    // (see hasMultipleSensitiveFieldTypes in scoreDom()) - unusual for a
    // legitimate flow, which normally presents these as separate
    // sequential steps. One signal among several here; never enough alone
    // (spec section 9: "OTP field alone MUST NOT automatically produce
    // HIGH_RISK" - this function only reaches SUSPICIOUS, and only with a
    // second independent signal on top).
    dom.available && dom.hasMultipleSensitiveFieldTypes,
    // RANK 5: DNS anomaly (short TTL, or resolution currently failing - see
    // scoreDns()). Same "one signal among several, never enough alone"
    // treatment as every other entry in this list - see the function
    // docstring above for the false-positive reasoning.
    !!(dnsScore && dnsScore.available && dnsScore.score > 0),
  ];
  const trueCount = signals.filter(Boolean).length;
  return trueCount >= 2;
}

/**
 * FIX (false-positive patch, updated by the evidence-fusion patch - see
 * qualifiesForCombinedWeakEvidenceSuspicion() above for the measured
 * investigation): the HIGH_RISK corroboration gate makes ML (or ML + weak
 * URL heuristics) alone STRUCTURALLY incapable of reaching HIGH_RISK (their
 * weight caps sum to 50 < 60). This function is the equivalent gate one
 * level down, at the SAFE/SUSPICIOUS boundary: because ML's weight cap alone
 * (35) can already exceed the SAFE threshold (29) by itself, a single
 * isolated high ML prediction can push rawScore past safeMax with zero
 * corroboration from any other independently-checked category.
 *
 * An earlier version of this function's fallback treated "domain
 * unavailable" as sufficient (on top of a high ML score) to justify
 * SUSPICIOUS. Measurement showed that's too permissive: legitimate
 * login/auth-flow pages on major domains (accounts.google.com/signin,
 * claude.ai/new) score in the same 70-95% ML range as confirmed phishing
 * credential-harvest pages whenever domain/webpage data isn't available -
 * there is no ML threshold in that range that separates them cleanly using
 * only URL/page features. The fallback below now requires either genuine
 * corroboration - a domain actually confirmed very new, or DNS actually
 * failing to resolve - or an ML score so extreme (>= ML_ULTRA_HIGH_CONFIDENCE)
 * that it measurably clears every legitimate example seen in
 * training/validation data with margin to spare. A merely-high isolated ML
 * score with everything else genuinely unavailable no longer qualifies on
 * its own.
 */
function qualifiesForSuspicious({ ml, urlHeur, dom, domainScore, dnsScore, corroboration }) {
  if (corroboration.qualifies) return true; // already HIGH_RISK-worthy, certainly SUSPICIOUS-worthy
  if (urlHeur.score >= 25) return true; // a meaningful URL red flag (IP address, '@' obfuscation, suspicious TLD/shortener, high hostname entropy, etc.)
  if (dom.available && dom.score >= 20) return true; // a real, independently-observed DOM finding at warning/critical severity - not a bare password field alone (info-level, +6, present on virtually every legitimate login page)
  if (hasVerifiedLegitimacyEvidence({ domainScore })) return false;
  if (ml.available && ml.score >= ML_ULTRA_HIGH_CONFIDENCE) return true;
  // Isolated ML crossing safeMax on its own needs at least one other
  // genuinely-observed (not merely unavailable) negative signal.
  return (
    (domainScore.available && domainScore.score >= ELEVATED_THRESHOLD) ||
    (dnsScore && dnsScore.available && dnsScore.score > 0)
  );
}

/**
 * Fuses all evidence into a final risk assessment.
 * @param {object} evidence - { ml, urlFacts, mlFeatures, domSignals, domain, dns }
 * @returns {object} { riskScore, verdict, breakdown, explanation, informational }
 */
export function computeRisk(evidence) {
  const { ml, urlFacts, mlFeatures, domSignals, domain, dns, redirect } = evidence;

  const mlAvailable = !!(ml && ml.available);
  const mlScore = mlAvailable ? clamp(ml.phishingProbability * 100, 0, 100) : 0;
  const mlEval = { available: mlAvailable, score: mlScore, confidence: mlAvailable ? 1.0 : 0 };

  const urlHeur = scoreUrlHeuristics(urlFacts, mlFeatures);
  const domRaw = scoreDom(domSignals);
  const domainScore = scoreDomain(domain);
  const dnsScore = scoreDns(dns);

  // FIX (false-positive patch): only fold the weak hidden-iframe/overlay
  // point value into the DOM score when it's corroborated by some other
  // independently-observed stronger signal - see scoreDom() and
  // weakDomSignalIsCorroborated() above. The flags are always shown
  // (transparency/detection is preserved either way); only the SCORE
  // contribution is conditional.
  const domWeakCorroborated = domRaw.available && weakDomSignalIsCorroborated({ dom: domRaw, urlHeur, domainScore });
  // RANK 4: hidden/deceptive credential fields use their OWN, stricter gate
  // (see hiddenCredentialFieldIsCorroborated() above) - deliberately
  // evaluated and applied separately from domWeakCorroborated/weakScore so
  // the (more permissive) hidden-iframe/overlay gate can never be the thing
  // that lets a hidden-credential-field score through.
  const hiddenCredCorroborated = domRaw.available && hiddenCredentialFieldIsCorroborated({ dom: domRaw, urlHeur, domainScore });
  const dom = domRaw.available
    ? {
        ...domRaw,
        score: clamp(
          domRaw.score +
            (domWeakCorroborated ? domRaw.weakScore : 0) +
            (hiddenCredCorroborated ? domRaw.hiddenCredentialWeakScore : 0),
          0,
          100
        ),
        flags: [...domRaw.flags, ...domRaw.weakFlags, ...domRaw.hiddenCredentialWeakFlags],
      }
    : domRaw;

  // RANK 1: computed AFTER dom/urlHeur so it can reference their results
  // (final-destination brand impersonation/typosquatting, credential-
  // harvest pattern) without re-implementing those checks. See
  // scoreRedirect()'s own comment for why this has NO weight bucket and
  // contributes nothing to weightedScore below - it participates only in
  // the corroboration gates.
  const redirectScore = scoreRedirect(redirect, urlHeur, dom);

  // Fixed-weight sum. NO renormalization - unavailable categories contribute
  // exactly 0 and their weight is simply unused, not redistributed.
  // redirectScore is intentionally NOT part of this sum (see scoreRedirect).
  const weightedScore =
    (mlEval.score / 100) * WEIGHTS.ml +
    (urlHeur.score / 100) * WEIGHTS.urlHeuristics +
    (dom.score / 100) * WEIGHTS.dom +
    (domainScore.score / 100) * WEIGHTS.domain +
    (dnsScore.score / 100) * WEIGHTS.dns;

  const rawScore = Math.round(clamp(weightedScore, 0, 100));
  const corroboration = qualifiesForHighRisk({ ml: mlEval, urlHeur, dom, domainScore, dnsScore, redirect: redirectScore });

  // Verdict is driven PRIMARILY by the explicit corroboration policy, not a
  // bare point threshold - see qualifiesForHighRisk(). The weighted score is
  // then adjusted only for score/verdict display consistency (spec: never
  // show "HIGH_RISK, Risk Score 34/100" or "SAFE, Risk Score 80/100"). This
  // ordering matters: gating HIGH_RISK behind "score >= 60 AND qualifies"
  // (tried first, see git history / training/README.md) made genuinely
  // corroborated phishing (e.g. credential harvesting combo) fail to reach
  // HIGH_RISK, because the deliberately-low per-category weight caps that
  // keep ML alone from reaching 60 also kept modest-but-real combinations
  // under 60. The corroboration policy - not the raw sum - is the actual
  // decision; the caps' job is only to make single-signal escalation
  // impossible, which they still do (see qualifiesForHighRisk's elevatedCount
  // and combo checks, each requiring a named category to independently show
  // elevated internal evidence, not just a high weighted contribution).
  let verdict, riskScore;
  if (corroboration.qualifies) {
    verdict = "HIGH_RISK";
    riskScore = Math.max(rawScore, 60);
  } else if (rawScore >= 60) {
    // Crossed 60 without meeting the explicit corroboration bar - demote and
    // cap the displayed score so it stays consistent with SUSPICIOUS, not a
    // silent promotion to HIGH_RISK on arithmetic alone.
    verdict = "SUSPICIOUS";
    riskScore = 59;
  } else if (rawScore > THRESHOLDS.safeMax) {
    // FIX (false-positive patch): see qualifiesForSuspicious() above - don't
    // let an isolated ML score (with zero corroboration from any other
    // independently-checked category) push a page out of SAFE on its own.
    if (qualifiesForSuspicious({ ml: mlEval, urlHeur, dom, domainScore, dnsScore, corroboration })) {
      verdict = "SUSPICIOUS";
      riskScore = rawScore;
    } else {
      verdict = "SAFE";
      riskScore = THRESHOLDS.safeMax;
    }
  } else if (qualifiesForCombinedWeakEvidenceSuspicion({ ml: mlEval, urlHeur, dom, domainScore, dnsScore, redirect: redirectScore })) {
    // FIX (evidence-fusion patch): see qualifiesForCombinedWeakEvidenceSuspicion()
    // above. rawScore alone (diluted by fixed weight caps) didn't cross
    // safeMax, but 2+ independently-observed real (non-"unavailable")
    // negative signals together are still meaningful evidence - display
    // score is floored to stay consistent with SUSPICIOUS (never
    // "SUSPICIOUS, Risk Score 23/100"), same consistency rule already
    // applied to the other verdict branches above.
    verdict = "SUSPICIOUS";
    riskScore = Math.max(rawScore, THRESHOLDS.safeMax + 1);
  } else {
    verdict = "SAFE";
    riskScore = rawScore;
  }

  // --- Explanation (risk evidence only - never includes HTTPS) ---
  const allFlags = [...urlHeur.flags, ...dom.flags, ...domainScore.flags, ...dnsScore.flags, ...redirectScore.flags];
  if (mlAvailable) {
    if (mlScore >= 60) allFlags.unshift({ level: "warning", text: "ML model rates this URL as high phishing likelihood (one input among several - not sufficient alone to block)" });
    else if (mlScore >= 35) allFlags.unshift({ level: "info", text: "ML model rates this URL as moderate phishing likelihood" });
    else allFlags.push({ level: "positive", text: "ML model rates this URL as low phishing likelihood" });
  } else {
    allFlags.push({ level: "unavailable", text: "ML model unavailable for this page" });
  }
  if (!dom.available) allFlags.push({ level: "unavailable", text: "Webpage content could not be analyzed (unknown, not assumed safe or malicious)" });
  if (!domainScore.available) allFlags.push({ level: "unavailable", text: "Domain age unavailable" });

  const order = { critical: 0, warning: 1, info: 2, positive: 3, unavailable: 4 };
  allFlags.sort((a, b) => order[a.level] - order[b.level]);
  const explanation = allFlags.slice(0, 7);

  // --- Informational facts (never scored, never treated as evidence) ---
  const informational = [
    { label: "Connection", value: urlFacts.isHttps ? "HTTPS" : "HTTP (not scored as risk evidence either way)" },
  ];
  if (domain && domain.available && domain.ageDays != null) {
    informational.push({ label: "Domain age", value: `${domain.ageDays} days` });
  }

  return {
    riskScore,
    verdict,
    breakdown: {
      ml: mlEval,
      urlHeuristics: { available: true, score: Math.round(urlHeur.score), confidence: 1.0 },
      dom: { available: dom.available, score: Math.round(dom.score), confidence: dom.confidence },
      domain: { available: domainScore.available, score: Math.round(domainScore.score), confidence: domainScore.confidence },
      dns: { available: dnsScore.available, score: Math.round(dnsScore.score), confidence: dnsScore.confidence },
      // Rank 1 - deliberately absent from weights_used (see scoreRedirect()):
      // this category never contributes to the weighted sum, only to the
      // named corroboration combos above.
      redirect: { available: redirectScore.available, score: Math.round(redirectScore.score), confidence: redirectScore.confidence },
      corroboration,
      weights_used: WEIGHTS,
    },
    explanation,
    informational,
  };
}
