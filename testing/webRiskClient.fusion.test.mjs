// [OFFLINE TEST] js/webRiskClient.js - fuseWebRiskIntoRisk()
//
// Imports the REAL, unmodified production file directly. No shim needed:
// fuseWebRiskIntoRisk() is a pure function that never touches chrome.* APIs
// (only checkWebRisk()/getConfiguredBackendUrl() do, and neither is called
// here), and its only import (./utils.js) is itself plain, dependency-free
// JS. This is genuinely exercising production code, not a reimplementation.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fuseWebRiskIntoRisk, threatTypeLabel } from "../js/webRiskClient.js";

function originalRisk(verdict, riskScore, extra = {}) {
  return {
    riskScore,
    verdict,
    breakdown: { ml: { score: 10, weight: 40, available: true } },
    explanation: [{ level: "info", text: "synthetic baseline evidence for this test" }],
    informational: false,
    ...extra,
  };
}

function webRisk(state, opts = {}) {
  const checkedAt = "2026-09-16T00:00:00.000Z";
  if (state === "match") {
    return {
      available: true,
      provider: "Google Web Risk",
      matched: true,
      threatTypes: opts.threatTypes || ["SOCIAL_ENGINEERING"],
      expireTime: opts.expireTime ?? null,
      checkedAt,
      error: null,
    };
  }
  if (state === "no_match") {
    return { available: true, provider: "Google Web Risk", matched: false, threatTypes: [], expireTime: null, checkedAt, error: null };
  }
  return { available: false, provider: "Google Web Risk", matched: false, threatTypes: [], expireTime: null, checkedAt, error: "Web Risk unavailable" };
}

// --- A. SAFE + MATCH ---------------------------------------------------------
test("[OFFLINE] A. SAFE(29) + MATCH -> final HIGH_RISK, original score preserved separately", () => {
  const original = originalRisk("SAFE", 29);
  const snapshotBefore = JSON.stringify(original);
  const final = fuseWebRiskIntoRisk(original, webRisk("match"));

  assert.equal(final.verdict, "HIGH_RISK");
  assert.ok(final.riskScore >= 60);
  assert.equal(final.originalVerdict, "SAFE");
  assert.equal(final.originalRiskScore, 29);
  assert.equal(final.webRiskOverride, true);
  assert.equal(JSON.stringify(original), snapshotBefore, "fuseWebRiskIntoRisk must never mutate its input");
});

// --- B. SUSPICIOUS + MATCH ---------------------------------------------------
test("[OFFLINE] B. SUSPICIOUS(42) + MATCH -> final HIGH_RISK, original score preserved separately", () => {
  const original = originalRisk("SUSPICIOUS", 42);
  const final = fuseWebRiskIntoRisk(original, webRisk("match"));

  assert.equal(final.verdict, "HIGH_RISK");
  assert.ok(final.riskScore >= 60);
  assert.equal(final.originalVerdict, "SUSPICIOUS");
  assert.equal(final.originalRiskScore, 42);
  assert.equal(final.webRiskOverride, true);
});

// --- C. HIGH_RISK + MATCH ----------------------------------------------------
test("[OFFLINE] C. HIGH_RISK(75) + MATCH -> remains HIGH_RISK, score unchanged (Web Risk corroborates, doesn't need to escalate further)", () => {
  const original = originalRisk("HIGH_RISK", 75);
  const final = fuseWebRiskIntoRisk(original, webRisk("match"));

  assert.equal(final.verdict, "HIGH_RISK");
  assert.equal(final.riskScore, 75);
});

// --- D/E. NO_MATCH must never touch the existing verdict/score -------------
test("[OFFLINE] D. SAFE(29) + NO_MATCH -> remains SAFE, score unchanged", () => {
  const original = originalRisk("SAFE", 29);
  const final = fuseWebRiskIntoRisk(original, webRisk("no_match"));
  assert.equal(final.verdict, "SAFE");
  assert.equal(final.riskScore, 29);
  assert.equal(final.webRiskOverride, false);
});

test("[OFFLINE] E. SUSPICIOUS(42) + NO_MATCH -> remains SUSPICIOUS, score unchanged", () => {
  const original = originalRisk("SUSPICIOUS", 42);
  const final = fuseWebRiskIntoRisk(original, webRisk("no_match"));
  assert.equal(final.verdict, "SUSPICIOUS");
  assert.equal(final.riskScore, 42);
  assert.equal(final.webRiskOverride, false);
});

// --- F/G. UNAVAILABLE must never touch the existing verdict/score ----------
test("[OFFLINE] F. SAFE(29) + UNAVAILABLE -> remains SAFE, score unchanged", () => {
  const original = originalRisk("SAFE", 29);
  const final = fuseWebRiskIntoRisk(original, webRisk("unavailable"));
  assert.equal(final.verdict, "SAFE");
  assert.equal(final.riskScore, 29);
  assert.equal(final.webRiskOverride, false);
});

test("[OFFLINE] G. SUSPICIOUS(42) + UNAVAILABLE -> remains SUSPICIOUS, score unchanged", () => {
  const original = originalRisk("SUSPICIOUS", 42);
  const final = fuseWebRiskIntoRisk(original, webRisk("unavailable"));
  assert.equal(final.verdict, "SUSPICIOUS");
  assert.equal(final.riskScore, 42);
  assert.equal(final.webRiskOverride, false);
});

// --- H. No arbitrary +50 / flat-100 score fabrication -----------------------
test("[OFFLINE] H. escalation score is exactly max(original, 60) - never +50, never a flat 100", () => {
  for (const originalScore of [0, 5, 15, 29, 30, 42, 59]) {
    const final = fuseWebRiskIntoRisk(originalRisk("SAFE", originalScore), webRisk("match"));
    assert.equal(final.riskScore, Math.max(originalScore, 60), `original ${originalScore} -> expected max(${originalScore},60)`);
    assert.notEqual(final.riskScore, originalScore + 50, "must not be the original score plus an arbitrary +50");
    assert.notEqual(final.riskScore, 100, "must not fabricate a flat 100");
  }
});

// --- I. Escalation is represented separately from the original score -------
test("[OFFLINE] I. escalated result always carries originalRiskScore/originalVerdict/webRisk/webRiskOverride distinctly from the final riskScore/verdict", () => {
  const original = originalRisk("SAFE", 29);
  const wr = webRisk("match", { threatTypes: ["MALWARE"] });
  const final = fuseWebRiskIntoRisk(original, wr);

  assert.notEqual(final.riskScore, final.originalRiskScore);
  assert.notEqual(final.verdict, final.originalVerdict);
  assert.equal(final.originalRiskScore, 29, "the true original PhishGuard score must still be recoverable");
  assert.equal(final.originalVerdict, "SAFE");
  assert.deepEqual(final.webRisk, wr, "the raw Web Risk result must be attached for the UI to render, unmodified");
  assert.equal(typeof final.webRiskOverride, "boolean");
  // The escalation must also be reflected as a distinct, clearly-labeled
  // explanation entry (spec: qualified language, never "confirmed"):
  assert.match(final.explanation[0].text, /Google Web Risk/);
  assert.doesNotMatch(final.explanation[0].text, /confirmed/i);
});

// --- Supporting behavior -----------------------------------------------------
test("[OFFLINE] fuseWebRiskIntoRisk is referentially transparent (same inputs -> deep-equal outputs)", () => {
  const original = originalRisk("SAFE", 29);
  const wr = webRisk("match");
  const first = fuseWebRiskIntoRisk(original, wr);
  const second = fuseWebRiskIntoRisk(original, wr);
  assert.deepEqual(first, second);
  assert.notEqual(first, original, "must return a new object, never the same reference");
});

test("[OFFLINE] the 'not yet checked' placeholder (available:false, pending:true) used by background.js's emptyRecord() is treated as a safe passthrough", () => {
  const original = originalRisk("SAFE", 29);
  const pending = { available: false, pending: true, provider: "Google Web Risk", matched: false, threatTypes: [], expireTime: null, checkedAt: null, error: null };
  const final = fuseWebRiskIntoRisk(original, pending);
  assert.equal(final.verdict, "SAFE");
  assert.equal(final.riskScore, 29);
  assert.equal(final.webRiskOverride, false);
});

test("[OFFLINE] threatTypeLabel() maps the three documented Web Risk threat types to human-readable labels, else null", () => {
  assert.equal(threatTypeLabel("SOCIAL_ENGINEERING"), "Social Engineering");
  assert.equal(threatTypeLabel("MALWARE"), "Malware");
  assert.equal(threatTypeLabel("UNWANTED_SOFTWARE"), "Unwanted Software");
  assert.equal(threatTypeLabel("SOMETHING_UNKNOWN"), null);
});
