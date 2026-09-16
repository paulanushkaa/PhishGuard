// PhishGuard v5.5.0 + Web Risk - warning interstitial script.

const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("blocked") || "";
const score = params.get("score") || "-";
const reason = params.get("reason") || "";
const threatType = params.get("threatType") || "";

document.getElementById("wn-score").textContent = score;
document.getElementById("wn-url").textContent = blockedUrl;

// EXTERNAL THREAT-INTELLIGENCE VALIDATION LAYER: the Google attribution box
// is shown ONLY when background.js explicitly set reason=webrisk - i.e. this
// specific warning was caused by a Web Risk MATCH (see
// maybeRedirectToWarning() in background.js). An ordinary PhishGuard-only
// HIGH_RISK warning (no reason param) never shows this block, per spec
// section 21's "do not incorrectly attach the Google attribution to
// warnings generated solely from PhishGuard's own ML/heuristics."
const THREAT_TYPE_MESSAGES = {
  SOCIAL_ENGINEERING: "This URL is suspected to be associated with phishing or other deceptive activity, per Google Web Risk.",
  MALWARE: "This URL is suspected to host malicious software, per Google Web Risk.",
  UNWANTED_SOFTWARE: "This URL is suspected to be associated with unwanted software, per Google Web Risk.",
};
if (reason === "webrisk") {
  const box = document.getElementById("wn-webrisk-box");
  if (box) {
    document.getElementById("wn-webrisk-text").textContent =
      THREAT_TYPE_MESSAGES[threatType] || "Google Web Risk identified this URL as a potentially unsafe resource.";
    box.style.display = "block";
  }
}

document.getElementById("wn-back-btn").addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    chrome.tabs.getCurrent((tab) => {
      if (tab) chrome.tabs.update(tab.id, { url: "chrome://newtab" });
    });
  }
});

document.getElementById("wn-proceed-btn").addEventListener("click", () => {
  chrome.tabs.getCurrent((tab) => {
    if (!tab || !blockedUrl) return;
    chrome.runtime.sendMessage(
      { type: "PHISHGUARD_PROCEED_ANYWAY", tabId: tab.id, url: blockedUrl },
      () => {
        /* background.js performs the navigation */
      }
    );
  });
});
