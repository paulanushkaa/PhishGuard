// backend/lib/rateLimitPolicy.js - rate limit test.
//
// Runs the REAL, unmodified factories from lib/rateLimitPolicy.js as REAL
// express-rate-limit middleware, mounted on a REAL Express app served by a
// REAL http.Server on an ephemeral local port, exercised with REAL HTTP
// requests. This is the same request path server.js itself uses in
// production, and the same path a live smoke test already proved works
// (real server, real 30/min cap, real 429s with proper headers).
//
// Why this replaced the previous version: the real express-rate-limit
// package validates that it has been handed a genuine Express request
// (req.ip, req.socket, app.get('trust proxy') all need to resolve to real
// values) before it will run at all. A bare `{}` object - which is all the
// offline shim ever needed - fails that validation immediately with
// ERR_ERL_UNDEFINED_IP_ADDRESS against the real package. A real HTTP request
// through a real Express app gives the real package everything it expects,
// with no mocking of req/res required anywhere in this file.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const express = require("express");
const {
  createWebRiskLimiter,
  createWebRiskDailyLimiter,
  createHealthLimiter,
} = require("../lib/rateLimitPolicy");

function buildServer(routes) {
  // routes: { [path]: middleware } - each path gets its own limiter
  // instance, mounted on ONE app/server so a "do these share state"
  // question can be asked from a single client (matches how server.js
  // mounts distinct limiters on distinct routes of the one app).
  const app = express();
  app.set("trust proxy", false); // matches server.js's production default
  for (const [path, middleware] of Object.entries(routes)) {
    app.get(path, middleware, (req, res) => res.status(200).json({ ok: true }));
  }
  return http.createServer(app);
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  await new Promise((resolve) => server.close(resolve));
}

async function fireN(baseUrl, path, n) {
  const results = [];
  for (let i = 0; i < n; i++) {
    const res = await fetch(`${baseUrl}${path}`);
    const body = await res.json().catch(() => null);
    results.push({ blocked: res.status === 429, status: res.status, body });
  }
  return results;
}

test("createWebRiskLimiter: allows exactly WEBRISK_RATE_LIMIT_MAX requests, blocks the next one with the documented message shape", async () => {
  const original = process.env.WEBRISK_RATE_LIMIT_MAX;
  process.env.WEBRISK_RATE_LIMIT_MAX = "3";
  const limiter = createWebRiskLimiter(); // limit captured at creation time
  process.env.WEBRISK_RATE_LIMIT_MAX = original;

  const server = buildServer({ "/webrisk": limiter });
  const baseUrl = await listen(server);
  try {
    const results = await fireN(baseUrl, "/webrisk", 4);
    assert.deepEqual(results.slice(0, 3).map((r) => r.blocked), [false, false, false], "first 3 requests must pass through");
    assert.equal(results[3].blocked, true, "the 4th request must be blocked");
    assert.equal(results[3].status, 429);
    assert.equal(results[3].body.success, false);
    assert.equal(results[3].body.matched, false, "a rate-limited response must never look like a Web Risk MATCH");
    assert.match(results[3].body.error, /rate limit/i);
  } finally {
    await close(server);
  }
});

test("createWebRiskDailyLimiter: independently enforces its own (larger) cap with its own message", async () => {
  const original = process.env.WEBRISK_DAILY_RATE_LIMIT_MAX;
  process.env.WEBRISK_DAILY_RATE_LIMIT_MAX = "2";
  const limiter = createWebRiskDailyLimiter();
  process.env.WEBRISK_DAILY_RATE_LIMIT_MAX = original;

  const server = buildServer({ "/webrisk-daily": limiter });
  const baseUrl = await listen(server);
  try {
    const results = await fireN(baseUrl, "/webrisk-daily", 3);
    assert.equal(results[2].blocked, true);
    assert.match(results[2].body.error, /daily/i);
  } finally {
    await close(server);
  }
});

test("createHealthLimiter: independent cap, does not share state with the webrisk limiters", async () => {
  const originalHealth = process.env.HEALTH_RATE_LIMIT_MAX;
  process.env.HEALTH_RATE_LIMIT_MAX = "2";
  const healthLimiter = createHealthLimiter();
  process.env.HEALTH_RATE_LIMIT_MAX = originalHealth;
  const webriskLimiter = createWebRiskLimiter();

  // Both limiters are mounted on the SAME app/server, so requests come from
  // the same client (127.0.0.1) - the isolation being tested is that each
  // factory call creates its own independent counter, not that the client
  // differs.
  const server = buildServer({ "/health": healthLimiter, "/webrisk": webriskLimiter });
  const baseUrl = await listen(server);
  try {
    // Exhaust the health limiter...
    await fireN(baseUrl, "/health", 2);
    const healthBlocked = (await fireN(baseUrl, "/health", 1))[0].blocked;
    // ...the webrisk limiter must be completely unaffected (separate instance/state).
    const webriskStillOpen = !(await fireN(baseUrl, "/webrisk", 1))[0].blocked;

    assert.equal(healthBlocked, true, "health limiter should now be exhausted");
    assert.equal(webriskStillOpen, true, "webrisk limiter must not be affected by health traffic");
  } finally {
    await close(server);
  }
});

test("createWebRiskLimiter default (no env override) is tighter than the old shared 60/min it replaced", async () => {
  const original = process.env.WEBRISK_RATE_LIMIT_MAX;
  delete process.env.WEBRISK_RATE_LIMIT_MAX;
  const limiter = createWebRiskLimiter();
  process.env.WEBRISK_RATE_LIMIT_MAX = original;

  const server = buildServer({ "/webrisk": limiter });
  const baseUrl = await listen(server);
  try {
    const results = await fireN(baseUrl, "/webrisk", 61); // old shared limit was 60/min
    const firstBlockedIndex = results.findIndex((r) => r.blocked);
    assert.ok(firstBlockedIndex !== -1 && firstBlockedIndex < 60, "default cap must now trip before the old 60/min threshold");
  } finally {
    await close(server);
  }
});
