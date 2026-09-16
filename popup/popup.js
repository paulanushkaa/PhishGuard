// PhishGuard v5.0 - popup script.
// Only responsibility: request the current tab's analysis from background.js
// and render it. All detection logic lives in background.js/js/*.js so that
// closing the popup never interrupts protection.
//
// NOTE: HTTPS status is rendered in the "Page facts" section, NOT in "Why?" -
// it is informational only and is never scored as risk evidence in either
// direction (see js/riskEngine.js).

function setText(el, text) {
  if (el) el.textContent = text == null ? "-" : String(text);
}

function verdictLabel(verdict) {
  return { SAFE: "🟢 SAFE", SUSPICIOUS: "🟡 SUSPICIOUS", HIGH_RISK: "🔴 HIGH RISK" }[verdict] || verdict;
}

function layerText(available, scoreOrLabel) {
  return available ? scoreOrLabel : "Unavailable";
}

const WEBRISK_THREAT_LABELS = {
  SOCIAL_ENGINEERING: "Social Engineering",
  MALWARE: "Malware",
  UNWANTED_SOFTWARE: "Unwanted Software",
};

// Renders the External Threat Intelligence layer's THREE possible states
// (spec section 19/16) plus one purely cosmetic transient fourth state
// ("Checking…") while the backend request is still in flight - that state
// is never a fourth value the backend itself can return (see
// js/webRiskClient.js's emptyRecord() placeholder / three-state contract).
function webRiskDisplay(webRisk) {
  if (!webRisk || webRisk.pending) return { text: "Checking…", cls: "checking" };
  if (!webRisk.available) return { text: "Unavailable", cls: "unavailable" };
  if (webRisk.matched) {
    const label = WEBRISK_THREAT_LABELS[webRisk.threatTypes && webRisk.threatTypes[0]];
    return { text: label ? `Threat detected — ${label}` : "Threat detected", cls: "threat" };
  }
  return { text: "No threat match", cls: "clean" };
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function renderUnavailable() {
  document.getElementById("pg-loading").style.display = "none";
  document.getElementById("pg-content").style.display = "none";
  document.getElementById("pg-unavailable").style.display = "block";
}

function renderAnalysis(record, tab) {
  document.getElementById("pg-loading").style.display = "none";
  document.getElementById("pg-unavailable").style.display = "none";
  document.getElementById("pg-content").style.display = "block";

  let hostname = "-";
  try { hostname = new URL(record.url).hostname; } catch (e) { /* ignore */ }
  setText(document.getElementById("pg-domain"), hostname);
  setText(document.getElementById("pg-url-value"), record.url);

  const risk = record.finalRisk || record.risk;
  const badge = document.getElementById("pg-verdict-badge");
  const scoreEl = document.getElementById("pg-score-value");
  const fill = document.getElementById("pg-meter-fill");

  const noteEl = document.getElementById("pg-original-note");

  if (!risk) {
    setText(badge, "Analyzing…");
    badge.className = "pg-verdict-badge";
    setText(scoreEl, "-");
    if (noteEl) noteEl.style.display = "none";
  } else {
    setText(badge, verdictLabel(risk.verdict));
    badge.className = "pg-verdict-badge " + risk.verdict.toLowerCase();
    setText(scoreEl, `${risk.riskScore} / 100`);
    fill.style.left = `${Math.min(97, Math.max(1, risk.riskScore))}%`;

    const b = risk.breakdown;
    setText(
      document.getElementById("pg-layer-ml"),
      layerText(b.ml.available, b.ml.score >= 60 ? "High Likelihood" : b.ml.score >= 35 ? "Moderate Likelihood" : "Low Likelihood")
    );
    const domHasMinorSignals =
      b.dom.available &&
      Array.isArray(risk.explanation) &&
      risk.explanation.some((item) =>
        /hidden iframe|invisible full-page overlay|multiple cross-origin iframes/i.test(item?.text || "")
      );
    setText(
      document.getElementById("pg-layer-dom"),
      layerText(
        b.dom.available,
        b.dom.score >= 40
          ? "Threats Found"
          : domHasMinorSignals
            ? "Minor Signals"
            : "No Major Threats"
      )
    );
    setText(
      document.getElementById("pg-layer-domain"),
      layerText(b.domain.available, b.domain.score >= 40 ? "Very New" : b.domain.score > 0 ? "New" : "Established")
    );

    // EXTERNAL THREAT-INTELLIGENCE VALIDATION LAYER (Google Web Risk) - the
    // one new field this integration adds to the popup (spec section 19).
    const webRiskEl = document.getElementById("pg-layer-webrisk");
    if (webRiskEl) {
      const wr = webRiskDisplay(risk.webRisk);
      setText(webRiskEl, wr.text);
      webRiskEl.className = "pg-layer-value pg-webrisk-" + wr.cls;
    }

    // "Final Risk Score" vs "PhishGuard's own score" distinction (spec
    // section 28) - only ever shown when a Web Risk match actually changed
    // the verdict, never fabricated or implied otherwise.
    if (noteEl) {
      if (risk.webRiskOverride) {
        setText(
          noteEl,
          `Escalated by Google Web Risk. PhishGuard's own analysis alone scored this ${verdictLabel(risk.originalVerdict)} (${risk.originalRiskScore}/100).`
        );
        noteEl.style.display = "block";
      } else {
        noteEl.style.display = "none";
      }
    }
  }

  const list = document.getElementById("pg-reasons-list");
  while (list.firstChild) list.removeChild(list.firstChild);
  const reasons = (risk && risk.explanation) || [];
  for (const r of reasons) {
    const li = document.createElement("li");
    li.className = r.level;
    li.textContent = r.text;
    list.appendChild(li);
  }
  if (reasons.length === 0) {
    const li = document.createElement("li");
    li.className = "info";
    li.textContent = "Still gathering evidence…";
    list.appendChild(li);
  }

  const factsList = document.getElementById("pg-facts-list");
  while (factsList.firstChild) factsList.removeChild(factsList.firstChild);
  const facts = (risk && risk.informational) || [];
  for (const f of facts) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = f.label + ": ";
    const value = document.createElement("b");
    value.textContent = f.value;
    li.appendChild(label);
    li.appendChild(value);
    factsList.appendChild(li);
  }
}

let currentTab = null;

function requestAndRenderAnalysis(tab) {
  chrome.runtime.sendMessage({ type: "PHISHGUARD_GET_ANALYSIS", tabId: tab.id }, (record) => {
    if (chrome.runtime.lastError || !record) return;
    renderAnalysis(record, tab);
  });
}

async function main() {
  document.getElementById("pg-settings-btn").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  const tab = await getActiveTab();
  if (!tab || !tab.url) {
    renderUnavailable();
    return;
  }
  currentTab = tab;

  chrome.runtime.sendMessage({ type: "PHISHGUARD_GET_ANALYSIS", tabId: tab.id }, (record) => {
    if (chrome.runtime.lastError) {
      renderUnavailable();
      return;
    }
    if (!record) {
      renderUnavailable();
      return;
    }
    renderAnalysis(record, tab);
  });
}

main();

// Live-refresh once shortly after opening, in case async evidence (domain/
// DNS) resolved just after the popup requested the first snapshot.
setTimeout(() => {
  if (currentTab) requestAndRenderAnalysis(currentTab);
}, 1200);

// DOM/webpage evidence in particular can legitimately arrive later than the
// one-shot check above (document_idle + settle delay + debounced re-scans
// on heavier/SPA pages). background.js pushes PHISHGUARD_ANALYSIS_UPDATED
// over the same message channel the instant fresh DOM evidence lands for
// this tab, however late - re-fetch and re-render right away rather than
// leaving the popup stuck on a stale "Webpage: Unavailable" snapshot. This
// is push-driven (no polling loop): it only fires when background.js has
// something new to report.
chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "PHISHGUARD_ANALYSIS_UPDATED" && currentTab && message.tabId === currentTab.id) {
    requestAndRenderAnalysis(currentTab);
  }
});
