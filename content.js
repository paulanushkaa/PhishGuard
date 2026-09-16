// PhishGuard v5.0 - content script.
//
// Responsible for webpage/DOM inspection: forms, password fields, iframes,
// scripts, links, and a few lightweight page-behavior signals. Sends a
// structured evidence object to background.js via chrome.runtime.sendMessage.
// Never blocks the page; never scans continuously (debounced + limited
// MutationObserver, one-shot on load plus a bounded number of re-scans).
//
// If this script fails to run at all (page blocked, Safe Browsing
// interstitial, restricted page, offline, etc.), background.js's DOM
// evidence for this page simply stays at its default { available: false } -
// which js/riskEngine.js treats as UNKNOWN (contributes 0, never "safe",
// never "malicious"), not as an implicit "nothing found."

// NOTE ON MODULE LOADING:
// Chrome does not support "type": "module" for manifest-declared
// content_scripts (unlike the background service_worker, which does).
// A top-level `import` statement here would throw "Cannot use import
// statement outside a module" because Chrome always loads manifest
// content scripts as classic (non-module) scripts. Dynamic import()
// works from a classic script and always loads its target as a real ES
// module regardless of how that target is declared, so we use it here
// instead. The imported file (js/psl.js) is unchanged - same exports,
// same logic - and must be listed in manifest.json's
// web_accessible_resources so this page-context dynamic import (and
// psl.js's own internal fetch of js/psl_data.json) is allowed to load it.
//
// Everything below is wrapped in an async IIFE (rather than top-level
// await) for the same reason: top-level await also requires module
// context, which manifest content scripts don't get.
(async () => {

const SUSPICIOUS_KEYWORDS_LOCAL = [
  "login", "signin", "verify", "verification", "secure", "security",
  "account", "wallet", "payment", "billing", "update", "confirm",
  "authentication", "recover", "unlock", "suspended", "limited",
  "bank", "banking", "invoice", "password",
];

// Loaded once before any analysis runs. Using the REAL Public Suffix List
// here (not a naive hostname.split(".").slice(-2) heuristic) matters: the
// naive version would treat e.g. "shop.example.co.uk" and
// "totally-different-company.co.uk" as the "same registrable domain"
// (both reduce to "co.uk"), silently hiding a genuine cross-domain
// credential-submission red flag on any multi-part-TLD site.
let ensurePslLoaded, registrableDomainSync;
let _psl = null;
try {
  ({ ensurePslLoaded, registrableDomainSync } = await import(
    chrome.runtime.getURL("js/psl.js")
  ));
  _psl = await ensurePslLoaded();
} catch (e) {
  _psl = null; // handled per-call below - falls back to exact hostname match only
}

function sameRegistrableDomain(hostA, hostB) {
  if (!hostA || !hostB) return false;
  const a = hostA.toLowerCase();
  const b = hostB.toLowerCase();
  if (a === b) return true;
  if (!_psl) return false; // PSL failed to load - be conservative, don't claim same-origin
  return registrableDomainSync(a, _psl) === registrableDomainSync(b, _psl);
}

function analyzeForms() {
    const forms = Array.from(document.forms || []);
    let hasPasswordField = false;
    let hasCrossOriginFormAction = false;
    let formActionMissingOrSuspicious = false;
    let crossOriginFormCount = 0;

    for (const form of forms) {
      const passwordInputs = form.querySelectorAll('input[type="password"]');
      if (passwordInputs.length > 0) hasPasswordField = true;

      // RANK 4 FIX (cross-origin-submission gap): js/riskEngine.js's
      // scoreDom() was already written to treat ANY sensitive field type -
      // password, OTP, or payment/card (see its own "broadened from
      // password field to any sensitive field type" comment) - the same
      // way when combined with cross-origin submission. This function,
      // however, only ever set hasCrossOriginFormAction for a form
      // containing a PASSWORD field - a form containing ONLY an OTP or
      // payment field submitting cross-domain (spec section 2C/3: "payment
      // + login credentials", "a payment form submits to a different
      // registrable domain") was silently invisible to that stronger
      // scoring path. Reuses the SAME isOtpInput/isPaymentInput
      // attribute-based checks defined below (function declarations are
      // hoisted within this IIFE, so they're available here even though
      // textually defined later) - never a second, separate detection
      // rule - scoped to inputs inside THIS form only.
      const formInputs = Array.from(form.querySelectorAll("input"));
      const hasSensitiveInput =
        passwordInputs.length > 0 || formInputs.some((inp) => isOtpInput(inp) || isPaymentInput(inp));

      const action = form.getAttribute("action");
      if (hasSensitiveInput) {
        if (!action || action.trim() === "") {
          // Missing action = submits to current page, which is normal; only
          // flag as "suspicious" if combined with other odd attributes.
        } else {
          try {
            const actionUrl = new URL(action, window.location.href);
            const crossOrigin = !sameRegistrableDomain(actionUrl.hostname, window.location.hostname);
            if (crossOrigin) {
              crossOriginFormCount++;
              hasCrossOriginFormAction = true;
            }
          } catch (e) {
            formActionMissingOrSuspicious = true;
          }
        }
      } else if (action) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (!sameRegistrableDomain(actionUrl.hostname, window.location.hostname)) {
            crossOriginFormCount++;
          }
        } catch (e) {
          /* ignore malformed action on non-credential forms */
        }
      }
    }

    return { hasPasswordField, hasCrossOriginFormAction, formActionMissingOrSuspicious, crossOriginFormCount };
  }

  // --- B1: form-less SPA credential detection -------------------------------
  // analyzeForms() above only sees password inputs inside a native <form>.
  // Modern SPA login (and SPA-style phishing) pages routinely use standalone
  // <input type="password"> elements with no <form> ancestor at all -
  // JavaScript, not native form submission, handles "login". A bare password
  // input is completely ordinary on its own (present on countless legitimate
  // sites), so a form-less one is only treated as part of a credential
  // interface when it has LOCAL, bounded corroboration - a nearby
  // identifier field (email/username) and/or a nearby submit-style control
  // using login/sign-in wording. This intentionally mirrors, rather than
  // replaces, the existing <form>-based signal: the result is folded into
  // the same `hasPasswordField` flag below (see runAnalysis()), so it flows
  // through the exact same weak, capped scoring path js/riskEngine.js
  // already applies to a bare password field (a few info-level points; never
  // sufficient on its own to promote a verdict - see riskEngine.js's
  // qualifiesForSuspicious()/qualifiesForCombinedWeakEvidenceSuspicion(),
  // which both already explicitly exclude "a bare password field alone").
  // riskEngine.js itself is not modified.
  //
  // Context is kept deliberately LOCAL (a few DOM levels, not full-page text)
  // so an unrelated heading like "How to build a login page" elsewhere on
  // the page can never count as corroboration for an unrelated password
  // field. Only DOM structure/attributes/text are inspected - password
  // input VALUES are never read.

  const LOGIN_CONTEXT_KEYWORDS = [
    "login", "log in", "sign in", "signin", "sign-in", "verify",
    "verification", "authenticate", "authentication", "account",
    "continue", "secure", "unlock",
  ];
  const IDENTIFIER_HINT_PATTERN = /user|email|login|identifier/i;
  // Fixed, small ancestor climb - bounds how "local" nearby context is.
  const LOCAL_CONTEXT_MAX_LEVELS = 4;

  function getLocalContainer(el) {
    let node = el.parentElement;
    let container = node;
    for (let i = 0; i < LOCAL_CONTEXT_MAX_LEVELS && node; i++) {
      container = node;
      if (node.tagName === "BODY" || node.tagName === "HTML") break;
      node = node.parentElement;
    }
    return container || el.parentElement || el;
  }

  function isIdentifierInput(input) {
    // Weak contextual signal only (never standalone evidence - see
    // nearbyLoginLanguageControlExists() below for the same caveat): an
    // email-type input, or a text/tel input whose name/id/placeholder/
    // autocomplete hints at being a username/identifier field.
    const type = (input.getAttribute("type") || "text").toLowerCase();
    if (type === "email") return true;
    if (type !== "text" && type !== "tel") return false;
    const hints = [
      input.getAttribute("name"),
      input.getAttribute("id"),
      input.getAttribute("placeholder"),
      input.getAttribute("autocomplete"),
    ].filter(Boolean).join(" ");
    return IDENTIFIER_HINT_PATTERN.test(hints);
  }

  function nearbyLoginLanguageControlExists(container) {
    const controls = Array.from(
      container.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"]')
    ).slice(0, 20); // bounded - a local container has no legitimate reason to have more
    for (const c of controls) {
      const text = [c.textContent, c.getAttribute("value"), c.getAttribute("aria-label")]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (LOGIN_CONTEXT_KEYWORDS.some((k) => text.includes(k))) return true;
    }
    return false;
  }

  function analyzeFormlessCredentialFields() {
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'))
      .filter((inp) => !inp.closest("form"))
      .slice(0, 25); // bounded - avoid pathological pages with huge input counts

    for (const pw of passwordInputs) {
      const container = getLocalContainer(pw);
      const identifierNearby = Array.from(container.querySelectorAll("input")).some(
        (other) => other !== pw && isIdentifierInput(other)
      );
      if (identifierNearby || nearbyLoginLanguageControlExists(container)) {
        return { hasFormlessCredentialField: true };
      }
    }
    return { hasFormlessCredentialField: false };
  }

  // --- RANK 4: OTP / payment field detection -------------------------------
  // Broadens "sensitive field" detection beyond passwords: a credential-
  // harvesting page doesn't always ask for a password specifically - a
  // one-time-code (OTP) or card/payment-only harvesting page is just as
  // real a pattern. Detection is deliberately attribute-based (autocomplete
  // token, name/id/placeholder wording) rather than reading field VALUES,
  // and - like every other single DOM signal in this file - is only ever
  // one input among several to js/riskEngine.js, never sufficient alone
  // (see riskEngine.js's scoreDom(): a bare OTP/payment field scores the
  // same small, capped amount a bare password field already does, and only
  // becomes strong evidence when paired with cross-origin submission).
  const OTP_HINT_PATTERN = /otp|one.?time.?code|verification.?code|auth.?code|2fa|security.?code/i;
  const PAYMENT_HINT_PATTERN = /card.?number|cvv|cvc|cvv2|exp(iry|iration)?.?date|cc.?number|cc.?exp/i;

  function isOtpInput(input) {
    const type = (input.getAttribute("type") || "text").toLowerCase();
    const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
    if (autocomplete === "one-time-code") return true;
    if (!["text", "tel", "number"].includes(type)) return false;
    const hints = [input.getAttribute("name"), input.getAttribute("id"), input.getAttribute("placeholder")]
      .filter(Boolean).join(" ");
    return OTP_HINT_PATTERN.test(hints);
  }

  function isPaymentInput(input) {
    const type = (input.getAttribute("type") || "text").toLowerCase();
    const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
    if (autocomplete.startsWith("cc-")) return true;
    if (!["text", "tel", "number"].includes(type)) return false;
    const hints = [input.getAttribute("name"), input.getAttribute("id"), input.getAttribute("placeholder")]
      .filter(Boolean).join(" ");
    return PAYMENT_HINT_PATTERN.test(hints);
  }

  function analyzeSensitiveFields() {
    // Bounded scan - same defensive cap rationale as elsewhere in this file
    // (pathological pages with huge input counts must never make this scan
    // expensive).
    const inputs = Array.from(document.querySelectorAll("input")).slice(0, 300);
    let hasOtpField = false;
    let hasPaymentField = false;
    for (const inp of inputs) {
      if (!hasOtpField && isOtpInput(inp)) hasOtpField = true;
      if (!hasPaymentField && isPaymentInput(inp)) hasPaymentField = true;
      if (hasOtpField && hasPaymentField) break;
    }
    return { hasOtpField, hasPaymentField };
  }

  // --- RANK 4: hidden/deceptive credential field detection ------------------
  // A password, one-time-code, or payment INPUT that is present and
  // interactive but made invisible to the user (display:none,
  // visibility:hidden, effectively zero-size, fully transparent, or
  // positioned far off-canvas) is a known technique for silently harvesting
  // browser-autofilled credentials, OTPs, or payment data without ever
  // showing the user a visible form. Detection is CSS/layout state only -
  // field VALUES are never read, and the check never treats `type="hidden"`
  // inputs (an entirely different, ubiquitous mechanism used for CSRF
  // tokens/form state on virtually every legitimate site) as a match, since
  // `isSensitiveInput` below only recognizes input[type=password] and the
  // SAME isOtpInput/isPaymentInput attribute-based checks already used
  // above - none of which a type="hidden" input can ever satisfy.
  //
  // This signal is DELIBERATELY treated as weak and gated in
  // js/riskEngine.js (see hiddenCredentialFieldIsCorroborated()), never
  // scored on its own: a hidden decoy password field is also a known
  // LEGITIMATE technique some real login forms use to steer browser autofill
  // away from the wrong field, so "hidden credential field" must never, by
  // itself or merely alongside an ordinary visible login form, move a
  // page's score - only when paired with a genuinely independent red flag.
  const OFFSCREEN_PX_THRESHOLD = -500; // far beyond any legitimate layout offset

  function isHiddenOrOffscreen(el) {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    if (style.display === "none" || style.visibility === "hidden") return true;
    if (parseFloat(style.opacity || "1") === 0) return true;
    if (rect.width <= 1 && rect.height <= 1) return true;
    if (style.position === "absolute" || style.position === "fixed") {
      const left = parseFloat(style.left);
      const top = parseFloat(style.top);
      if ((!Number.isNaN(left) && left <= OFFSCREEN_PX_THRESHOLD) || (!Number.isNaN(top) && top <= OFFSCREEN_PX_THRESHOLD)) {
        return true;
      }
    }
    return false;
  }

  function analyzeHiddenCredentialFields() {
    const inputs = Array.from(document.querySelectorAll("input")).slice(0, 300);
    let hiddenCredentialFieldCount = 0;
    for (const inp of inputs) {
      const type = (inp.getAttribute("type") || "text").toLowerCase();
      const isSensitive = type === "password" || isOtpInput(inp) || isPaymentInput(inp);
      if (!isSensitive) continue;
      try {
        if (isHiddenOrOffscreen(inp)) hiddenCredentialFieldCount++;
      } catch (e) {
        /* getComputedStyle/getBoundingClientRect should not throw, but stay defensive */
      }
    }
    return { hiddenCredentialFieldCount };
  }

  function analyzeIframes() {
    const iframes = Array.from(document.querySelectorAll("iframe"));
    let hiddenIframeCount = 0;
    let crossOriginIframeCount = 0;

    for (const frame of iframes) {
      const style = window.getComputedStyle(frame);
      const rect = frame.getBoundingClientRect();
      const isHidden =
        style.display === "none" ||
        style.visibility === "hidden" ||
        (rect.width <= 1 && rect.height <= 1) ||
        parseFloat(style.opacity || "1") === 0;
      if (isHidden) hiddenIframeCount++;

      const src = frame.getAttribute("src");
      if (src) {
        try {
          const srcUrl = new URL(src, window.location.href);
          if (!sameRegistrableDomain(srcUrl.hostname, window.location.hostname)) {
            crossOriginIframeCount++;
          }
        } catch (e) {
          /* ignore malformed iframe src */
        }
      }
    }
    return { hiddenIframeCount, crossOriginIframeCount, totalIframes: iframes.length };
  }

  function analyzeScriptsAndLinks() {
    const scripts = Array.from(document.querySelectorAll("script[src]"));
    let externalScriptCount = 0;
    for (const s of scripts) {
      try {
        const srcUrl = new URL(s.getAttribute("src"), window.location.href);
        if (!sameRegistrableDomain(srcUrl.hostname, window.location.hostname)) externalScriptCount++;
      } catch (e) {
        /* ignore */
      }
    }

    const links = Array.from(document.querySelectorAll("a[href]"));
    let externalLinkCount = 0;
    for (const a of links.slice(0, 500)) {
      // cap to avoid scanning huge link-heavy pages expensively
      try {
        const hrefUrl = new URL(a.getAttribute("href"), window.location.href);
        if (!sameRegistrableDomain(hrefUrl.hostname, window.location.hostname)) externalLinkCount++;
      } catch (e) {
        /* ignore */
      }
    }

    return {
      totalScripts: scripts.length,
      externalScriptCount,
      totalLinks: links.length,
      externalLinkCount,
    };
  }

  function analyzeBehavior() {
    const flags = [];
    // Detect a contextmenu-blocking listener via a lightweight synthetic
    // dispatch check is unreliable/expensive; instead check for the common
    // inline pattern via computed heuristics is out of scope for a passive
    // scan. We limit this to cheap, reliable DOM-state checks only.

    // Large invisible overlay covering the viewport (common credential-
    // harvesting overlay pattern layered on top of a legitimate-looking page).
    const all = document.querySelectorAll("div, section");
    const OVERLAY_SCAN_LIMIT = 300;
    // Sample both the start and the end of the candidate list so a bounded
    // scan doesn't systematically miss overlays appended late in the DOM
    // (previously only the first 300 elements were ever inspected).
    const overlayScanIndices = new Set();
    for (let i = 0; i < Math.min(all.length, OVERLAY_SCAN_LIMIT); i++) overlayScanIndices.add(i);
    if (all.length > OVERLAY_SCAN_LIMIT) {
      for (let i = Math.max(0, all.length - OVERLAY_SCAN_LIMIT); i < all.length; i++) overlayScanIndices.add(i);
    }
    let overlayCount = 0;
    for (const i of overlayScanIndices) {
      const el = all[i];
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      const coversViewport =
        rect.width >= window.innerWidth * 0.9 &&
        rect.height >= window.innerHeight * 0.9 &&
        (style.position === "fixed" || style.position === "absolute");
      const isInvisible =
        parseFloat(style.opacity || "1") === 0 || style.visibility === "hidden";
      if (coversViewport && isInvisible) overlayCount++;
    }
    if (overlayCount > 0) {
      flags.push("Invisible full-page overlay detected (possible click/credential capture layer)");
    }

    return { suspiciousBehaviorFlags: flags };
  }

  function runAnalysis() {
    try {
      const forms = analyzeForms();
      // B1: a form-less password field only ever ADDS to hasPasswordField
      // (never overrides it to false) - existing <form>-based detection is
      // unchanged; see analyzeFormlessCredentialFields() above.
      const formless = analyzeFormlessCredentialFields();
      const sensitiveFields = analyzeSensitiveFields(); // RANK 4
      const hiddenCredentialFields = analyzeHiddenCredentialFields(); // RANK 4
      const iframes = analyzeIframes();
      const scriptsLinks = analyzeScriptsAndLinks();
      const behavior = analyzeBehavior();

      const bodyText = (document.body && document.body.innerText || "").slice(0, 5000).toLowerCase();
      const keywordHits = SUSPICIOUS_KEYWORDS_LOCAL.filter((k) => bodyText.includes(k));

      return {
        available: true,
        url: window.location.href,
        ...forms,
        hasPasswordField: forms.hasPasswordField || formless.hasFormlessCredentialField,
        ...sensitiveFields,
        ...hiddenCredentialFields,
        ...iframes,
        ...scriptsLinks,
        ...behavior,
        visibleKeywordCount: keywordHits.length,
      };
    } catch (e) {
      return { available: false, reason: `DOM analysis failed: ${e.message}` };
    }
  }

  function sendAnalysis() {
    const result = runAnalysis();
    try {
      chrome.runtime.sendMessage({ type: "PHISHGUARD_DOM_ANALYSIS", payload: result });
    } catch (e) {
      // Extension context may be invalidated (e.g. during reload) - fail silently.
    }
  }

  // Initial scan shortly after load (let the page settle a bit).
  if (document.readyState === "complete" || document.readyState === "interactive") {
    setTimeout(sendAnalysis, 300);
  } else {
    window.addEventListener("DOMContentLoaded", () => setTimeout(sendAnalysis, 300));
  }

  // Bounded, debounced re-scan on significant DOM mutations (e.g. SPA
  // navigation or late-injected forms/iframes) - NOT continuous scanning.
  let debounceTimer = null;
  let rescanCount = 0;
  const MAX_RESCANS = 5;
  const observer = new MutationObserver(() => {
    if (rescanCount >= MAX_RESCANS) {
      observer.disconnect();
      return;
    }
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      rescanCount++;
      sendAnalysis();
    }, 1500);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

})();
