// PhishGuard v5.0 - Domain & DNS intelligence.
//
// Both integrations here are free, public, and require NO API key:
//  - RDAP (rdap.org bootstrap) for domain registration/age data
//  - Google Public DNS-over-HTTPS JSON API for A/AAAA/MX/NS records
//
// Per project requirements: these are enhancements only. On any failure
// (network error, timeout, CORS block, unexpected response shape, registry
// not supporting RDAP) we report { available: false } - NEVER a guessed or
// fabricated value. The core extension (URL + ML + DOM analysis) must keep
// working with these layers entirely absent.

import { fetchWithTimeout, TtlCache } from "./utils.js";

const domainCache = new TtlCache(30 * 60 * 1000); // 30 min
const dnsCache = new TtlCache(10 * 60 * 1000); // 10 min

/**
 * Best-effort domain registration/age lookup via RDAP.
 * Returns { available, ageDays, registrationDate, registrar, raw } or
 * { available: false, reason }.
 */
export async function getDomainIntelligence(registrableDomain) {
  if (!registrableDomain) return { available: false, reason: "No registrable domain" };
  const cached = domainCache.get(registrableDomain);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`,
      { headers: { Accept: "application/rdap+json" } },
      4000
    );
    if (!res.ok) {
      const result = { available: false, reason: `RDAP lookup returned HTTP ${res.status}` };
      domainCache.set(registrableDomain, result);
      return result;
    }
    const data = await res.json();
    const events = Array.isArray(data.events) ? data.events : [];
    const regEvent = events.find((e) => e.eventAction === "registration");
    const registrationDate = regEvent ? regEvent.eventDate : null;

    let registrar = null;
    if (Array.isArray(data.entities)) {
      const registrarEntity = data.entities.find(
        (e) => Array.isArray(e.roles) && e.roles.includes("registrar")
      );
      if (registrarEntity && Array.isArray(registrarEntity.vcardArray)) {
        const vcard = registrarEntity.vcardArray[1];
        if (Array.isArray(vcard)) {
          const fnEntry = vcard.find((f) => f[0] === "fn");
          if (fnEntry) registrar = fnEntry[3];
        }
      }
    }

    let ageDays = null;
    if (registrationDate) {
      const regTime = new Date(registrationDate).getTime();
      if (!Number.isNaN(regTime)) {
        ageDays = Math.max(0, Math.floor((Date.now() - regTime) / (1000 * 60 * 60 * 24)));
      }
    }

    const result = {
      available: registrationDate != null,
      ageDays,
      registrationDate,
      registrar,
      reason: registrationDate == null ? "RDAP response did not include a registration date" : undefined,
    };
    domainCache.set(registrableDomain, result);
    return result;
  } catch (e) {
    const result = { available: false, reason: `Domain intelligence unavailable: ${e.message}` };
    domainCache.set(registrableDomain, result);
    return result;
  }
}

/**
 * Best-effort DNS lookup (A, AAAA, MX, NS) via Google's public DoH JSON API.
 * Returns { available, records: {A:[], AAAA:[], MX:[], NS:[]}, resolvesOk }
 * or { available: false, reason }.
 */
export async function getDnsRecords(hostname) {
  if (!hostname) return { available: false, reason: "No hostname" };
  const cached = dnsCache.get(hostname);
  if (cached) return cached;

  const types = ["A", "AAAA", "MX", "NS"];
  try {
    const responses = await Promise.all(
      types.map((t) =>
        fetchWithTimeout(
          `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${t}`,
          {},
          3500
        )
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null)
      )
    );

    const records = {};
    let anyResolved = false;
    const ttls = [];
    types.forEach((t, i) => {
      const body = responses[i];
      const answers = body && Array.isArray(body.Answer) ? body.Answer : [];
      records[t] = answers.map((a) => a.data);
      if (answers.length > 0) anyResolved = true;
      // RANK 5 (DNS anomaly): TTL is already present on every answer in the
      // response we just fetched - no extra network call needed. Only A/AAAA
      // TTLs are used (MX/NS TTLs vary for unrelated operational reasons and
      // aren't a meaningful fast-flux indicator).
      if (t === "A" || t === "AAAA") {
        for (const a of answers) {
          if (typeof a.TTL === "number" && a.TTL >= 0) ttls.push(a.TTL);
        }
      }
    });

    if (!responses.some((r) => r != null)) {
      const result = { available: false, reason: "DNS-over-HTTPS lookup failed for all record types" };
      dnsCache.set(hostname, result);
      return result;
    }

    const minTtl = ttls.length > 0 ? Math.min(...ttls) : null;
    const result = { available: true, records, resolvesOk: anyResolved, minTtl };
    dnsCache.set(hostname, result);
    return result;
  } catch (e) {
    const result = { available: false, reason: `DNS intelligence unavailable: ${e.message}` };
    dnsCache.set(hostname, result);
    return result;
  }
}
