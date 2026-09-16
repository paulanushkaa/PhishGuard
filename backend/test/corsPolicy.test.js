// [OFFLINE TEST] backend/lib/corsPolicy.js
// Pure function, no dependency on the "cors" or "express" packages, so this
// runs against the real, unmodified module with no shim needed.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { isAllowedOrigin } = require("../lib/corsPolicy");

test("[OFFLINE] corsPolicy: missing Origin header (server-to-server / curl / health checks) is allowed", () => {
  assert.equal(isAllowedOrigin(undefined, { configuredOrigins: [], nodeEnv: "production" }), true);
});

test("[OFFLINE] corsPolicy (Step 4): missing Origin header is REJECTED when requireOrigin:true - closes the naive bypass on the expensive route", () => {
  assert.equal(isAllowedOrigin(undefined, { configuredOrigins: [], nodeEnv: "production", requireOrigin: true }), false);
  assert.equal(isAllowedOrigin("", { configuredOrigins: [], nodeEnv: "production", requireOrigin: true }), false);
});

test("[OFFLINE] corsPolicy (Step 4): requireOrigin:true still allows a real, correctly-configured origin through - legitimate extension traffic is not broken", () => {
  const origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
  assert.equal(isAllowedOrigin(origin, { configuredOrigins: [origin], nodeEnv: "production", requireOrigin: true }), true);
});

test("[OFFLINE] corsPolicy (Step 4): requireOrigin defaults to false when omitted - /health's existing lenient behavior is unchanged", () => {
  assert.equal(isAllowedOrigin(undefined, { configuredOrigins: [], nodeEnv: "production" }), true);
});

test("[OFFLINE] corsPolicy: exact configured production origin is allowed", () => {
  const origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
  assert.equal(isAllowedOrigin(origin, { configuredOrigins: [origin], nodeEnv: "production" }), true);
});

test("[OFFLINE] corsPolicy: an unconfigured origin is rejected in production", () => {
  assert.equal(
    isAllowedOrigin("https://evil.example", { configuredOrigins: ["chrome-extension://realid"], nodeEnv: "production" }),
    false
  );
});

test("[OFFLINE] corsPolicy: an UNCONFIGURED chrome-extension:// origin is rejected in production (not auto-allowed just for being an extension)", () => {
  assert.equal(
    isAllowedOrigin("chrome-extension://some-other-extension-id", { configuredOrigins: ["chrome-extension://realid"], nodeEnv: "production" }),
    false
  );
});

test("[OFFLINE] corsPolicy: any chrome-extension:// origin is allowed in development (local unpacked-extension convenience)", () => {
  assert.equal(
    isAllowedOrigin("chrome-extension://whatever-local-dev-id", { configuredOrigins: [], nodeEnv: "development" }),
    true
  );
});

test("[OFFLINE] corsPolicy: localhost origins allowed in development, rejected in production unless explicitly configured", () => {
  assert.equal(isAllowedOrigin("http://localhost:5173", { configuredOrigins: [], nodeEnv: "development" }), true);
  assert.equal(isAllowedOrigin("http://127.0.0.1:5173", { configuredOrigins: [], nodeEnv: "development" }), true);
  assert.equal(isAllowedOrigin("http://localhost:5173", { configuredOrigins: [], nodeEnv: "production" }), false);
});

test("[OFFLINE] corsPolicy: a random third-party site is rejected in both environments", () => {
  assert.equal(isAllowedOrigin("https://attacker.example", { configuredOrigins: [], nodeEnv: "development" }), false);
  assert.equal(isAllowedOrigin("https://attacker.example", { configuredOrigins: [], nodeEnv: "production" }), false);
});

test("[OFFLINE] corsPolicy: preflight (OPTIONS) note - not independently testable offline", () => {
  // server.js wires isAllowedOrigin() into the `cors` npm package's
  // `origin(origin, callback)` option. The `cors` package itself (not our
  // code) is what intercepts OPTIONS preflight requests and calls this same
  // callback with the preflight's Origin header - so the decision surface
  // tested above IS what governs preflight too, but the HTTP-level OPTIONS
  // handling is inside the real "cors" package, which cannot be exercised
  // here without network access to `npm install` it (see checkpoint notes).
  // This test only documents that boundary; it makes no assertion.
  assert.ok(true);
});
