// backend/routes/webRisk.js - route test.
//
// Runs the REAL, unmodified router from routes/webRisk.js as REAL Express
// middleware, mounted on a REAL http.Server listening on an ephemeral local
// port, exercised with REAL HTTP requests. No shim, no reaching into
// framework internals (the previous version of this file relied on
// router._routes, an introspection property that only exists on the
// offline-only shim in testing/shims/node_modules/express - it does not
// exist on the real "express" package, so that approach cannot work against
// real dependencies at all).
//
// The one thing still substituted for a real Google Web Risk call is
// global.fetch, exactly as before - services/webRiskService.js's checkUrl()
// takes `fetchImpl = fetch` as a *default parameter*, evaluated at call time
// against whatever `fetch` resolves to in scope, so overriding global.fetch
// here reaches the real, unmodified checkUrl()/buildRequestUrl() logic
// without changing a single line of production code. What's different from
// the old version: our test client no longer uses the (now-mocked) global
// fetch to talk to our own local server - it uses `originalFetch`, a
// reference to the real fetch captured before any mocking happens, so the
// two things overriding `fetch` might affect (our own outgoing test
// request, vs. the handler's outgoing request to "Google") can never be
// confused with each other.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const express = require("express");

const FAKE_KEY = "test-key-never-a-real-google-key";
const originalFetch = global.fetch; // captured BEFORE any test mocks fetch
const originalKey = process.env.GOOGLE_WEB_RISK_API_KEY;

// Load the REAL, unmodified router and mount it exactly as server.js does
// (at /api/webrisk, with express.json() ahead of it) - a real Express app
// start to finish, just without server.js's CORS/rate-limit layers, which
// are their own files with their own dedicated tests (corsPolicy.test.js,
// rateLimitPolicy.test.js). This file's job is the route handler itself.
const webRiskRouter = require("../routes/webRisk");

let server;
let baseUrl;

test.before(async () => {
  process.env.GOOGLE_WEB_RISK_API_KEY = FAKE_KEY;

  const app = express();
  app.set("logErrors", false); // keeps test output clean; same flag production reads
  app.use(express.json());
  app.use("/api/webrisk", webRiskRouter);
  // Mirrors (does not import - server.js has no separate module to import
  // this from) server.js's own central error handler. Needed because
  // express.json() defaults to strict mode: a top-level JSON literal like
  // `null` is rejected as a SyntaxError by body-parser BEFORE the router
  // ever runs, and in production that error reaches exactly this kind of
  // handler, which is what turns it into the normalized {success:false,
  // error} shape instead of Express's default HTML error page. Without this,
  // the non-object-body test below would not reflect what a real deployment
  // actually returns.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.status(err.status || 500).json({ success: false, error: err.message });
  });

  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  process.env.GOOGLE_WEB_RISK_API_KEY = originalKey;
  global.fetch = originalFetch;
  await new Promise((resolve) => server.close(resolve));
});

/** Sends a REAL HTTP request to our REAL local Express server, using the
 * REAL fetch captured above - never the mocked global.fetch a given test may
 * have set for simulating Google's response inside the handler. Passing
 * `null` sends the JSON literal `null` (JSON.stringify(null) === "null"),
 * which express.json() parses back to JS `null` - see the non-object-body
 * test below. */
async function postCheck(body) {
  const res = await originalFetch(`${baseUrl}/api/webrisk/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, body: json };
}

function jsonFetchResponse(status, respBody) {
  return async () => ({ ok: status >= 200 && status < 300, status, json: async () => respBody });
}

function assertNormalizedShape(body) {
  const keys = Object.keys(body).sort();
  assert.deepEqual(keys, ["checkedAt", "error", "expireTime", "matched", "provider", "success", "threatTypes"].sort());
  assert.equal(body.provider, "Google Web Risk");
  assert.ok(!JSON.stringify(body).includes(FAKE_KEY), "response body must never contain the API key");
}

// --- Valid request + MATCH --------------------------------------------------
test("POST /check: valid URL + Web Risk MATCH -> success:true, matched:true, threat data preserved", async () => {
  global.fetch = jsonFetchResponse(200, { threat: { threatTypes: ["SOCIAL_ENGINEERING"], expireTime: "2099-01-01T00:00:00Z" } });
  const { status, body } = await postCheck({ url: "https://phishy.example/login" });
  assert.equal(status, 200);
  assertNormalizedShape(body);
  assert.equal(body.success, true);
  assert.equal(body.matched, true);
  assert.deepEqual(body.threatTypes, ["SOCIAL_ENGINEERING"]);
  assert.equal(body.expireTime, "2099-01-01T00:00:00Z");
  assert.equal(body.error, null);
});

// --- Valid request + NO_MATCH -----------------------------------------------
test("POST /check: valid URL + Web Risk NO_MATCH ({} response) -> success:true, matched:false", async () => {
  global.fetch = jsonFetchResponse(200, {});
  const { status, body } = await postCheck({ url: "https://example.com" });
  assert.equal(status, 200);
  assertNormalizedShape(body);
  assert.equal(body.success, true);
  assert.equal(body.matched, false);
  assert.deepEqual(body.threatTypes, []);
  assert.equal(body.expireTime, null);
});

// --- Malformed / missing URL (client error) ---------------------------------
test("POST /check: missing url field -> 400, success:false, Google never called", async () => {
  let called = false;
  global.fetch = async () => {
    called = true;
    return { ok: true, status: 200, json: async () => ({}) };
  };
  const { status, body } = await postCheck({});
  assert.equal(status, 400);
  assert.equal(body.success, false);
  assert.equal(called, false, "must reject before ever calling Web Risk");
});

test("POST /check: malformed URL string -> 400, success:false", async () => {
  global.fetch = async () => {
    throw new Error("should not be called");
  };
  const { status, body } = await postCheck({ url: "not a url" });
  assert.equal(status, 400);
  assert.equal(body.success, false);
});

test("POST /check: non-http(s) scheme (javascript:) -> 400, rejected", async () => {
  global.fetch = async () => {
    throw new Error("should not be called");
  };
  const { status, body } = await postCheck({ url: "javascript:alert(1)" });
  assert.equal(status, 400);
  assert.equal(body.success, false);
});

test("POST /check: non-object body (JSON literal null) -> 400", async () => {
  global.fetch = async () => {
    throw new Error("should not be called");
  };
  // JSON.stringify(null) sends the literal `null`, which express.json()
  // parses to JS null - the same "body is not an object" case the old fake
  // req exercised directly.
  const { status, body } = await postCheck(null);
  assert.equal(status, 400);
  assert.equal(body.success, false);
});

// --- Web Risk UNAVAILABLE paths (must never become MATCH or "safe") --------
test("POST /check: Google HTTP 500 -> normalized UNAVAILABLE (success:false), not a crash, not a match", async () => {
  global.fetch = jsonFetchResponse(500, { error: "internal" });
  const { status, body } = await postCheck({ url: "https://example.com" });
  assert.equal(status, 200); // route always responds 200 for a Web-Risk-side failure - see routes/webRisk.js
  assertNormalizedShape(body);
  assert.equal(body.success, false);
  assert.equal(body.matched, false);
  assert.ok(body.error, "an error message must be present");
});

test("POST /check: Google HTTP 429 (rate limited) -> UNAVAILABLE, never MATCH", async () => {
  global.fetch = jsonFetchResponse(429, { error: "rate limited" });
  const { body } = await postCheck({ url: "https://example.com" });
  assert.equal(body.success, false);
  assert.equal(body.matched, false);
});

test("POST /check: Google HTTP 403 (invalid API key) -> UNAVAILABLE, key never echoed back", async () => {
  global.fetch = jsonFetchResponse(403, { error: { message: `API key ${FAKE_KEY} not valid` } });
  const { body } = await postCheck({ url: "https://example.com" });
  assert.equal(body.success, false);
  assertNormalizedShape(body); // includes the "key never in response" assertion
});

test("POST /check: simulated timeout (fetch rejects with AbortError) -> UNAVAILABLE", async () => {
  // Exercises the same AbortError branch a real 4000ms timeout would hit
  // (services/webRiskService.js), via an immediately-rejecting mock rather
  // than waiting out the real timer - see backend/test/webRiskService.test.js
  // for a test that uses a genuine short timer instead.
  global.fetch = async () => {
    throw new DOMException("The operation was aborted.", "AbortError");
  };
  const { body } = await postCheck({ url: "https://example.com" });
  assert.equal(body.success, false);
  assert.match(body.error, /timed out/i);
});

test("POST /check: malformed (non-JSON) Google response -> UNAVAILABLE, not a crash", async () => {
  global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => {
      throw new Error("Unexpected token");
    },
  });
  const { body } = await postCheck({ url: "https://example.com" });
  assert.equal(body.success, false);
});

// --- Response never leaks the key, in ANY branch ----------------------------
test("POST /check: API key never present in the response body across match/no-match/error branches", async () => {
  for (const fetchImpl of [
    jsonFetchResponse(200, { threat: { threatTypes: ["MALWARE"] } }),
    jsonFetchResponse(200, {}),
    jsonFetchResponse(500, {}),
  ]) {
    global.fetch = fetchImpl;
    const { body } = await postCheck({ url: "https://example.com" });
    assert.ok(!JSON.stringify(body).includes(FAKE_KEY));
  }
});
