// PhishGuard v5.0 - Shared detection config lists.
//
// CRITICAL: This file MUST stay identical (same values) to
// training/lists_config.json. If you change a list here, mirror it there and
// retrain, or ML inference will drift from what the model was trained on.

export const MULTI_PART_TLDS = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
  "co.nz", "co.in", "co.jp", "co.kr", "com.br", "com.mx", "com.tr",
  "co.za", "com.sg", "com.hk", "co.id", "com.cn", "gov.in", "edu.in",
]);

export const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "xyz", "top", "gq", "ml", "cf", "ga", "tk", "buzz",
  "click", "link", "work", "support", "loan", "win", "review", "kim",
  "country", "science", "party", "gdn", "men", "download", "racing",
  "stream", "webcam", "accountant", "cricket", "faith", "date",
]);

export const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
  "rb.gy", "s.id", "v.gd", "shrtco.de", "clck.ru", "soo.gd",
]);

// Order matters only for keyword_hit_ratio's denominator (length); the set
// of words must match training/lists_config.json exactly.
export const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "verify", "verification", "secure", "security",
  "account", "wallet", "payment", "billing", "update", "confirm",
  "authentication", "recover", "unlock", "suspended", "limited",
  "bank", "banking", "invoice", "password",
];

export const SUSPICIOUS_SCHEMES = new Set(["data", "javascript", "vbscript", "file"]);

export const SUSPICIOUS_PORTS = new Set([8080, 8443, 4443, 4444, 6666, 6667, 1337]);

// Known brand names used only for the (weak, contextual) brand-impersonation
// heuristic in riskEngine.js - NOT used by the ML model. Kept short and
// maintainable per spec; add to this list rather than hard-coding brand
// checks elsewhere.
export const KNOWN_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
  "netflix", "bankofamerica", "wellsfargo", "citibank", "linkedin",
  "dropbox", "adobe", "ebay", "twitter", "spotify", "github", "steam",
  "coinbase", "binance", "walmart", "usps", "fedex", "dhl",
  "chase", "icloud", "whatsapp", "discord", "roblox", "interac", "sber",
  "absa", "santander",
];
