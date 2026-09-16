// PhishGuard v5.5.0 + Web Risk - options page script.
//
// SCOPE: this file configures exactly one thing - the PhishGuard BACKEND
// URL - and does nothing else. It never touches, requests, displays, or
// even knows about GOOGLE_WEB_RISK_API_KEY; that value lives only in the
// backend's own environment (see backend/.env.example) and never appears
// anywhere in this extension's source, storage, or network traffic.

import { DEFAULT_BACKEND_URL, STORAGE_KEY } from "../js/webRiskClient.js";

function setStatus(text, isError) {
  const el = document.getElementById("opt-status");
  el.textContent = text;
  el.style.color = isError ? "#ff6b6b" : "var(--pg-accent)";
}

function normalizeUrl(raw) {
  const trimmed = (raw || "").trim().replace(/\/+$/, "");
  if (!trimmed) return null;
  try {
    const u = new URL(trimmed);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return trimmed;
  } catch (e) {
    return null;
  }
}

async function loadCurrentUrl() {
  const input = document.getElementById("opt-backend-url");
  try {
    const stored = await chrome.storage.local.get(STORAGE_KEY);
    input.value = (stored && stored[STORAGE_KEY]) || DEFAULT_BACKEND_URL;
  } catch (e) {
    input.value = DEFAULT_BACKEND_URL;
  }
  input.placeholder = DEFAULT_BACKEND_URL;
}

async function saveBackendUrl() {
  const input = document.getElementById("opt-backend-url");
  const normalized = normalizeUrl(input.value);
  if (!normalized) {
    setStatus("Enter a valid http:// or https:// backend URL first.", true);
    return;
  }
  try {
    await chrome.storage.local.set({ [STORAGE_KEY]: normalized });
    input.value = normalized;
    setStatus("Saved. PhishGuard will use this backend on the next check.", false);
  } catch (e) {
    setStatus(`Could not save: ${e.message}`, true);
  }
}

async function testConnection() {
  const input = document.getElementById("opt-backend-url");
  const normalized = normalizeUrl(input.value);
  if (!normalized) {
    setStatus("Enter a valid http:// or https:// backend URL first.", true);
    return;
  }
  setStatus("Testing connection…", false);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);
  try {
    const res = await fetch(`${normalized}/health`, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) {
      setStatus(`Backend responded with HTTP ${res.status}.`, true);
      return;
    }
    const body = await res.json().catch(() => null);
    if (body && body.status === "ok") {
      setStatus("Connected - backend is reachable.", false);
    } else {
      setStatus("Backend reachable, but /health returned an unexpected response.", true);
    }
  } catch (e) {
    clearTimeout(timeout);
    setStatus(
      e.name === "AbortError" ? "Connection timed out after 4 seconds." : `Could not reach backend: ${e.message}`,
      true
    );
  }
}

async function resetToDefault() {
  const input = document.getElementById("opt-backend-url");
  input.value = DEFAULT_BACKEND_URL;
  setStatus("Reset to the default - click Save to apply.", false);
}

function main() {
  loadCurrentUrl();
  document.getElementById("opt-save-btn").addEventListener("click", saveBackendUrl);
  document.getElementById("opt-test-btn").addEventListener("click", testConnection);
  document.getElementById("opt-reset-btn").addEventListener("click", resetToDefault);
}

main();
