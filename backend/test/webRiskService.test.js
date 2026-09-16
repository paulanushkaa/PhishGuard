const test = require("node:test");
const assert = require("node:assert/strict");
const { checkUrl, WebRiskUnavailableError, buildRequestUrl, THREAT_TYPES } = require("../services/webRiskService");

const ORIGINAL_KEY = process.env.GOOGLE_WEB_RISK_API_KEY;
test.beforeEach(() => {
  process.env.GOOGLE_WEB_RISK_API_KEY = "test-key-not-real";
});
test.after(() => {
  process.env.GOOGLE_WEB_RISK_API_KEY = ORIGINAL_KEY;
});

function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

// --- Case: MATCH -----------------------------------------------------------
test("checkUrl: a threat.threatTypes response is a MATCH with expireTime preserved", async () => {
  const fetchImpl = async () =>
    jsonResponse(200, { threat: { threatTypes: ["SOCIAL_ENGINEERING"], expireTime: "2099-01-01T00:00:00Z" } });
  const result = await checkUrl("https://phishy.example/login", { fetchImpl });
  assert.equal(result.matched, true);
  assert.deepEqual(result.threatTypes, ["SOCIAL_ENGINEERING"]);
  assert.equal(result.expireTime, "2099-01-01T00:00:00Z");
});

// --- Case: NO MATCH ----------------------------------------------------------
test("checkUrl: an empty {} response (Google's documented no-match shape) is NO MATCH", async () => {
  const fetchImpl = async () => jsonResponse(200, {});
  const result = await checkUrl("https://example.com", { fetchImpl });
  assert.equal(result.matched, false);
  assert.deepEqual(result.threatTypes, []);
  assert.equal(result.expireTime, null);
});

test("checkUrl: a threat object with an empty threatTypes array is treated as NO MATCH, not a crash", async () => {
  const fetchImpl = async () => jsonResponse(200, { threat: { threatTypes: [] } });
  const result = await checkUrl("https://example.com", { fetchImpl });
  assert.equal(result.matched, false);
});

// --- Case: UNAVAILABLE (every failure mode) ---------------------------------
test("checkUrl: HTTP 500 -> UNAVAILABLE (never a match, never treated as safe)", async () => {
  const fetchImpl = async () => jsonResponse(500, { error: "server error" });
  await assert.rejects(() => checkUrl("https://example.com", { fetchImpl }), WebRiskUnavailableError);
});

test("checkUrl: HTTP 403 (invalid/restricted API key) -> UNAVAILABLE", async () => {
  const fetchImpl = async () => jsonResponse(403, { error: { message: "API key not valid" } });
  await assert.rejects(() => checkUrl("https://example.com", { fetchImpl }), WebRiskUnavailableError);
});

test("checkUrl: HTTP 429 (rate limited by Google) -> UNAVAILABLE, not MATCH", async () => {
  const fetchImpl = async () => jsonResponse(429, { error: "rate limited" });
  await assert.rejects(() => checkUrl("https://example.com", { fetchImpl }), WebRiskUnavailableError);
});

test("checkUrl: malformed (non-JSON-parseable) response -> UNAVAILABLE", async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => {
      throw new Error("Unexpected token in JSON");
    },
  });
  await assert.rejects(() => checkUrl("https://example.com", { fetchImpl }), WebRiskUnavailableError);
});

test("checkUrl: network failure (fetch rejects) -> UNAVAILABLE", async () => {
  const fetchImpl = async () => {
    throw new Error("getaddrinfo ENOTFOUND webrisk.googleapis.com");
  };
  await assert.rejects(() => checkUrl("https://example.com", { fetchImpl }), WebRiskUnavailableError);
});

test("checkUrl: request that never resolves -> times out -> UNAVAILABLE (never hangs)", async () => {
  const fetchImpl = (url, { signal }) =>
    new Promise((resolve, reject) => {
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      // deliberately never resolves on its own - only the abort should end this
    });
  const start = Date.now();
  await assert.rejects(() => checkUrl("https://example.com", { fetchImpl, timeoutMs: 50 }), WebRiskUnavailableError);
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 1000, `timeout should fire quickly (50ms configured), took ${elapsed}ms`);
});

test("checkUrl: missing GOOGLE_WEB_RISK_API_KEY -> UNAVAILABLE, and no request is even attempted", async () => {
  delete process.env.GOOGLE_WEB_RISK_API_KEY;
  let called = false;
  const fetchImpl = async () => {
    called = true;
    return jsonResponse(200, {});
  };
  await assert.rejects(() => checkUrl("https://example.com", { fetchImpl }), WebRiskUnavailableError);
  assert.equal(called, false, "must not call Google at all without a configured key");
  process.env.GOOGLE_WEB_RISK_API_KEY = "test-key-not-real";
});

// --- Request shape -----------------------------------------------------------
test("buildRequestUrl: uses the documented Lookup API endpoint, all three threat types, and never logs/exposes the key outside the URL param Google itself requires", () => {
  const url = buildRequestUrl("https://example.com/a?b=1", "MY_SECRET_KEY");
  assert.ok(url.startsWith("https://webrisk.googleapis.com/v1/uris:search?"));
  for (const t of THREAT_TYPES) assert.ok(url.includes(`threatTypes=${t}`));
  assert.ok(url.includes("key=MY_SECRET_KEY"));
  assert.ok(url.includes("uri="), "must include a uri parameter");
});
