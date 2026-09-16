// PhishGuard v5.1.1 - RANK 3: Punycode / IDN / mixed-script / homoglyph
// detection utilities.
//
// SCOPE: a small, self-contained, dependency-free Punycode (RFC 3492)
// decoder, plus a conservative homoglyph-confusable table and a minimal
// script classifier. This module performs NO scoring and NO brand
// comparison itself - it only turns an ASCII "xn--..." label back into the
// Unicode text it actually represents, so js/riskEngine.js's RANK 3
// section (see the "RANK 3" comments there) can look at what a label
// actually SAYS rather than just its ASCII-safe encoded form. All scoring/
// gating stays in js/riskEngine.js and is unchanged in shape by this file.
//
// SAFE BY CONSTRUCTION: every exported function is total (never throws)
// and never invents or destroys data.
//  - decodeIdnLabel() falls back to returning the ORIGINAL label unchanged
//    (wasIdn: false) on any malformed/unsupported input, so a callsite
//    that can't tell "decoded" from "not IDN" apart always fails safely
//    into treating it as an ordinary opaque label.
//  - normalizeHomoglyphsUnicode() only ever substitutes characters present
//    in the small table below; every other character (including digits,
//    hyphens, and any script the table doesn't cover) passes through
//    UNCHANGED. Callers that need a "fully collapsed to Latin" match (see
//    riskEngine.js's detectHomoglyphBrandImpersonation()) test the OUTPUT
//    against /^[a-z]+$/ themselves - this file makes no assumption about
//    what a caller intends to do with a partially-normalized result.
//  - This module never touches the real hostname/URL used for navigation,
//    display, or any other part of the extension (see featureExtractor.js
//    urlFacts().hostname, which is completely untouched by this file) -
//    it is read-only analysis support.

const PUNYCODE_BASE = 36;
const PUNYCODE_TMIN = 1;
const PUNYCODE_TMAX = 26;
const PUNYCODE_SKEW = 38;
const PUNYCODE_DAMP = 700;
const PUNYCODE_INITIAL_BIAS = 72;
const PUNYCODE_INITIAL_N = 128;
const PUNYCODE_DELIMITER = "-";
const PUNYCODE_MAX_OUTPUT_LENGTH = 256; // sanity cap - real hostname labels are <=63 bytes; guards against a pathological/adversarial input spinning the decode loop

/** RFC 3492 Bootstring bias adaptation. Same algorithm used by every
 * browser/DNS resolver's IDNA implementation - not novel or sensitive,
 * just the standard, publicly specified way to decode this encoding. */
function punycodeAdapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / PUNYCODE_DAMP) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) / 2) {
    delta = Math.floor(delta / (PUNYCODE_BASE - PUNYCODE_TMIN));
    k += PUNYCODE_BASE;
  }
  return k + Math.floor(((PUNYCODE_BASE - PUNYCODE_TMIN + 1) * delta) / (delta + PUNYCODE_SKEW));
}

/** Decodes a Punycode label BODY (i.e. the part after the "xn--" prefix)
 * into an array of Unicode code points. Throws on any malformed input -
 * callers (decodeIdnLabel below) always catch this and fall back to the
 * original ASCII label untouched. */
function punycodeDecode(input) {
  const output = [];
  let n = PUNYCODE_INITIAL_N;
  let i = 0;
  let bias = PUNYCODE_INITIAL_BIAS;

  let basicEnd = input.lastIndexOf(PUNYCODE_DELIMITER);
  if (basicEnd < 0) basicEnd = 0;
  for (let j = 0; j < basicEnd; j++) {
    const code = input.charCodeAt(j);
    if (code >= 0x80) throw new Error("invalid basic code point");
    output.push(code);
  }

  let idx = basicEnd > 0 ? basicEnd + 1 : 0;
  const len = input.length;
  while (idx < len) {
    if (output.length > PUNYCODE_MAX_OUTPUT_LENGTH) throw new Error("output too long");
    const oldi = i;
    let w = 1;
    for (let k = PUNYCODE_BASE; ; k += PUNYCODE_BASE) {
      if (idx >= len) throw new Error("truncated punycode input");
      const ch = input.charCodeAt(idx++);
      let digit;
      if (ch >= 48 && ch <= 57) digit = ch - 48 + 26; // '0'-'9' -> 26-35
      else if (ch >= 65 && ch <= 90) digit = ch - 65; // 'A'-'Z' -> 0-25
      else if (ch >= 97 && ch <= 122) digit = ch - 97; // 'a'-'z' -> 0-25
      else throw new Error("invalid punycode digit");
      if (digit > (Number.MAX_SAFE_INTEGER - i) / w) throw new Error("overflow");
      i += digit * w;
      const t = k <= bias ? PUNYCODE_TMIN : k >= bias + PUNYCODE_TMAX ? PUNYCODE_TMAX : k - bias;
      if (digit < t) break;
      w *= PUNYCODE_BASE - t;
    }
    const numPoints = output.length + 1;
    bias = punycodeAdapt(i - oldi, numPoints, oldi === 0);
    n += Math.floor(i / numPoints);
    i %= numPoints;
    if (n > 0x10ffff) throw new Error("invalid code point"); // beyond Unicode range
    output.splice(i, 0, n);
    i++;
  }
  return output;
}

/** Decodes one hostname LABEL (e.g. "xn--80ak6aa92e") to the Unicode text
 * it represents. Returns { text, wasIdn }.
 *  - Not an "xn--" label at all -> { text: label, wasIdn: false } (passed
 *    through completely unchanged - this is the common, non-IDN case).
 *  - Malformed/unsupported Punycode body -> SAME fallback, wasIdn: false.
 *    Never throws, never fails "open" into inventing a decoded value.
 *  - Otherwise -> { text: <decoded Unicode string>, wasIdn: true }.
 */
export function decodeIdnLabel(label) {
  const raw = label || "";
  const lower = raw.toLowerCase();
  if (!lower.startsWith("xn--")) return { text: raw, wasIdn: false };
  try {
    const codePoints = punycodeDecode(lower.slice(4));
    if (!codePoints.length) return { text: raw, wasIdn: false };
    return { text: String.fromCodePoint(...codePoints), wasIdn: true };
  } catch {
    return { text: raw, wasIdn: false };
  }
}

// Conservative Unicode script ranges, used ONLY to detect script MIXING
// within a single label - this is deliberately not a full Unicode script
// database (see spec: "Do NOT create an enormous arbitrary mapping").
// Digits, hyphens, and other punctuation are intentionally excluded from
// every script bucket below - they are common to all scripts, so mixing
// with them is not the suspicious pattern this is looking for.
const CYRILLIC_RE = /[\u0400-\u04FF]/;
const GREEK_RE = /[\u0370-\u03FF]/;
const LATIN_RE = /[a-z]/;

/** True if a single decoded label mixes 2+ of {Latin, Cyrillic, Greek}.
 * A label written ENTIRELY in one non-Latin script (ordinary, legitimate
 * IDN use - spec: "A domain entirely written in one legitimate non-Latin
 * script may be normal") does NOT count; only genuine within-label mixing
 * does, since that pattern has essentially no legitimate use case. */
export function isMixedScriptLabel(unicodeText) {
  const text = (unicodeText || "").toLowerCase();
  let scriptCount = 0;
  if (LATIN_RE.test(text)) scriptCount++;
  if (CYRILLIC_RE.test(text)) scriptCount++;
  if (GREEK_RE.test(text)) scriptCount++;
  return scriptCount >= 2;
}

// Conservative confusable table: ONLY characters that are reasonably
// defensible as visual look-alikes for a specific Latin letter (per spec's
// own worked examples), lowercase only (hostnames are already lowercased
// upstream - see featureExtractor.js's simpleUrlSplit()). Deliberately
// small and auditable - NOT an attempt at an exhaustive Unicode-confusables
// database (e.g. Unicode TR39). Any character not listed here is left
// UNCHANGED by normalizeHomoglyphsUnicode() below, which is what correctly
// keeps a genuine, wholly non-Latin domain from ever being coerced into
// looking like a Latin brand name by accident.
const HOMOGLYPH_UNICODE_MAP = {
  // Cyrillic
  "\u0430": "a", // а
  "\u0435": "e", // е
  "\u043e": "o", // о
  "\u0440": "p", // р
  "\u0441": "c", // с
  "\u0445": "x", // х
  "\u0443": "y", // у
  // Greek
  "\u03bf": "o", // ο
  "\u03c1": "p", // ρ
  "\u03bd": "v", // ν
  "\u03c7": "x", // χ
};

/** Applies the conservative confusable table above, character by
 * character. Characters not in the table (including digits, hyphens, and
 * any script not listed) pass through UNCHANGED - callers that require a
 * "fully collapsed to Latin" result (see riskEngine.js) test the OUTPUT
 * for that themselves; this function makes no such assumption on its
 * own. */
export function normalizeHomoglyphsUnicode(text) {
  let out = "";
  for (const ch of (text || "").toLowerCase()) out += HOMOGLYPH_UNICODE_MAP[ch] || ch;
  return out;
}
