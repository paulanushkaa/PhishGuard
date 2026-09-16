// PhishGuard v5.0 - shared utilities.

/** Simple TTL cache backed by a Map. Not persisted across service-worker
 * restarts by design (short-lived); use chrome.storage.session for longer
 * caching needs. */
export class TtlCache {
  constructor(ttlMs) {
    this.ttlMs = ttlMs;
    this.map = new Map();
  }
  get(key) {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() - entry.t > this.ttlMs) {
      this.map.delete(key);
      return undefined;
    }
    return entry.v;
  }
  set(key, value) {
    this.map.set(key, { v: value, t: Date.now() });
  }
  clearExpired() {
    const now = Date.now();
    for (const [k, entry] of this.map.entries()) {
      if (now - entry.t > this.ttlMs) this.map.delete(k);
    }
  }
}

export function debounce(fn, waitMs) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), waitMs);
  };
}

/** Fetch with a hard timeout - external services must never hang the UI. */
export async function fetchWithTimeout(url, options = {}, timeoutMs = 4000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

/** Safely sets text content (never innerHTML) - avoids any HTML injection
 * risk when rendering analysis results derived from page/URL content. */
export function setText(el, text) {
  if (!el) return;
  el.textContent = text == null ? "" : String(text);
}

export function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}
