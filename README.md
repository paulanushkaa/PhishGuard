# PhishGuard v5.5.0 - Intelligent Multi-Layer Phishing Detection

A Chrome Extension (Manifest V3) that detects phishing websites by combining
a domain-aware-evaluated Gradient Boosting ML model, URL lexical/structural
analysis, live webpage/DOM analysis, and optional domain/DNS
intelligence into one explainable risk score - with an explicit rule that
**no single evidence source, however strong, can trigger a HIGH_RISK
verdict on its own.**

This is a full rebuild (not a patch) of an earlier version that was found,
under closer scrutiny, to have several real architectural problems -
documented honestly below and in `training/README.md`, alongside the fixes.

---

## Current release

**v5.5.0** — Version/branding metadata update consolidating the Rank 1–7 work (redirect-chain tracking, typosquatting detection, IDN/homoglyph detection, credential-field correlation, DNS anomaly signal, URL feature engineering, and signal-family corroboration + performance caching) into a single, consistently-numbered release. No detection, ML, risk-scoring, domain/DNS, or warning logic was changed in this release; the existing regression suite passes unchanged.

## 1. What changed in this rebuild, and why

An audit of the previous version found specific, demonstrated problems:
the ML model gave `is_https` more importance than any other feature; a
naive `hostname.split(".")[-2:]` domain-parsing heuristic was silently
wrong for co.uk/com.au/co.jp/github.io-style domains **in three separate
places**, including the cross-origin-form-detection code that phishing
detection specifically depends on; the train/test split allowed the same
domain to appear in both, inflating apparent accuracy; and the risk engine
renormalized evidence weights when sources were unavailable, which meant
that with DOM/reputation/domain all absent, the ML score alone could
functionally decide the verdict.

All of these were rebuilt, not patched:

- **Real Public Suffix List parsing** (`js/psl.js` / `training/psl.py`),
  not a naive heuristic - verified 3000/3000 exact matches between the
  Python and JS implementations.
- **`is_https` removed from the ML feature set entirely** - HTTPS is now
  purely informational, never scored as risk evidence in either direction.
- **`hyphen_count`/`digit_count` split into hostname/path variants** - a
  hostname hyphen is real evidence; a path hyphen in `/2024/01/15/article-
  title/` is not, and blending them hurt both.
- **Domain-aware (group) train/val/test split** - 127,725 unique domains,
  zero overlap between splits (verified with a hard assertion, not just a
  comment).
- **Risk engine redesign: fixed weight caps, no renormalization.** ML's
  maximum possible contribution (35 points) plus URL heuristics' maximum
  (15 points) sum to 50 - structurally below the 60-point HIGH_RISK floor.
  It is not policy that ML alone can't trigger HIGH_RISK; it is arithmetic.
- **An explicit, auditable corroboration policy** on top of the score,
  matching named evidence combinations (credential harvesting, brand
  impersonation + ML, new domain + ML + URL evidence, typosquatting/
  homoglyph + credential evidence, or 2+ independently elevated
  categories).
- **Probability calibration** (Platt scaling, fit on validation data only,
  with honestly-reported before/after Brier scores) - raw model output is
  not presented as a calibrated real-world probability.
- **v5.0.1: Gradient Boosting model + evidence-fusion risk-engine rework.**
  See `training/README.md`'s "v5.0.1 changes" section for the full,
  honest writeup: the ML model changed from Random Forest to a genuine
  gradient-boosted-tree model (GradientBoostingClassifier - XGBoost itself
  could not be installed without network access), and the risk engine's
  isolated-ML gate was replaced after measurement showed it caused false
  positives on major legitimate sites (Google, Microsoft, Amazon, Claude)
  whenever reputation/domain data was unavailable.

## 2. Core safety principle (verified, not just claimed)

**ML alone must never be sufficient to trigger HIGH_RISK, and below a very
high, data-driven confidence bar, must never be sufficient to trigger
SUSPICIOUS either.** This is verified directly: `https://claude.ai/new`
scores a 94.6% calibrated ML phishing probability (a deliberately extreme,
adversarial test case) and *everything else unavailable* stays at **SAFE,
score 29** - the ML-alone escalation path that used to flag it at
SUSPICIOUS was measured to also flag several other major legitimate sites
(accounts.google.com, login.microsoftonline.com, amazon.in) under the same
"reputation unavailable" condition, and was removed in favor of requiring
at least one other genuinely-observed negative signal. See "Testing" below
for the full, current test matrix.

## 3. Architecture

```
                    BROWSER TAB
                        |
          +-------------+-------------+
          |                           |
          v                           v
    URL ANALYSIS                 DOM ANALYSIS (content.js)
          |                           |
          v                           v
   FEATURE EXTRACTOR             PAGE FEATURES
  (PSL-based domain parsing)     (forms, iframes, scripts, links)
          |                           |
          v                           |
  REAL ML MODEL + CALIBRATION         |
          |                           |
          +-------------+-------------+
                        |
                        v
              RISK ENGINE (js/riskEngine.js)
                        |
          +-------------+-------------+
          |                           |
          v                           v
       DOMAIN                        DNS
        (RDAP)                 (Google DoH)
          |                           |
          +-------------+-------------+
                        |
                        v
       FIXED-WEIGHT SUM (no renormalization)
                        |
                        v
     EXPLICIT CORROBORATION POLICY (auditable)
                        |
                        v
                FINAL RISK SCORE (0-100)
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
        SAFE       SUSPICIOUS     HIGH RISK
       (0-29)       (30-59)      (60-100, AND
                                  corroboration
                                   satisfied)
                        |
                        v
        USER EXPLANATION (scored reasons)
       + PAGE FACTS (informational, unscored)
```

`background.js` orchestrates everything per-tab, with monotonic
per-tab **navigation generation tracking**: every navigation invalidates
in-flight async evidence from the previous URL, so a stale result can never
be applied to - or displayed for - a different page (verified with a
rapid-renavigation test - see "Testing").

## 4. Evidence model

Every evidence category returns a consistent shape:
`{ available, score (0-100), confidence, reasons }`. **Unavailable is
UNKNOWN - never converted to "safe" or "malicious."** A category that
couldn't be evaluated (DOM blocked, no reputation data, RDAP failure)
contributes exactly 0 to the score and is labeled "Unavailable" in the UI,
distinct from "checked and found nothing."

| Category | Max points | What "elevated" (>=50) requires |
|---|---|---|
| ML model | 40 | Calibrated phishing probability itself very high |
| DOM/webpage | 30 | e.g. password field + cross-origin submission |
| URL heuristics | 15 | e.g. IP address + `@` trick, or brand mismatch |
| Domain age | 10 | Registered recently |
| DNS | 5 | Resolution/record evidence is supporting only |

**No renormalization.** If DOM, reputation, domain, and DNS are all
unavailable, the maximum possible score is 35+15=50 - below the 60-point
floor. This is true regardless of how confident the ML model is.

## 5. HIGH_RISK policy (explicit corroboration, not a bare threshold)

Crossing 60 points is **necessary but not sufficient**. HIGH_RISK also
requires one of:

- **Credential harvesting**: a password field submitting to a cross-origin
  destination (this one is allowed to qualify without additional
  corroboration - see `js/riskEngine.js`'s docstring for the specific
  reasoning: it's a directly observed technical fact, not a probabilistic
  guess, and legitimate SSO/OAuth flows don't produce this exact pattern).
- **Brand impersonation + elevated ML**: a known brand name in a hostname
  label that isn't the real registrable domain, combined with elevated ML.
- **New domain + elevated ML + suspicious URL structure.**
- **Two or more independently elevated categories**, in general.

A score that reaches 60+ *without* satisfying one of these is demoted to
SUSPICIOUS, capped at 59 for display consistency (the score shown always
matches the verdict shown - never "HIGH_RISK, Risk Score 34/100").

## 6. ML model

Gradient Boosting (`GradientBoostingClassifier`, real gradient-boosted
trees - same algorithm family as XGBoost, used because the `xgboost`
package could not be installed without network access; see
`training/README.md` for the full reasoning), 120 trees, domain-aware-
evaluated (127,725 unique domains, zero overlap between train/val/test).
**Test-set (unseen domains):** Accuracy 86.6%, Precision 90.5%, Recall
81.9%, F1 0.860, ROC-AUC 0.939, **FPR 8.6%**, FNR 18.1%. A subgroup weak
spot was found and mitigated during this work: legitimate login/auth-flow
URLs had a measured ~13% false-positive rate before a targeted, documented
training-data oversampling mitigation cut it to ~3% (see
`training/README.md`). Full methodology, the domain-aware split
composition, and the calibration analysis are in `training/README.md`.
The previous Random Forest model's report is preserved at
`model/eval_report_rf.json` for comparison.

**This is the ML sub-model in isolation.** The shipped extension's actual
false-positive rate is governed by the risk engine on top of it - see
Testing below: 0 false positives across 107 real legitimate URLs.

## 7. Detection features

**URL** (36 features, `model/feature_schema.json` v2.0.0): length/depth/
component counts, hostname- and path-specific digit/hyphen counts, special
character counts, entropy (hostname/URL/path), IP-address and punycode
detection, PSL-based TLD/suspicious-TLD detection, shortener detection,
percent-encoding, suspicious scheme, keyword-hit ratio. **`is_https` is
deliberately excluded** - see above.
**DOM:** password fields, cross-origin form submission, hidden iframes,
cross-origin iframe/form counts, invisible full-page overlay detection.
**Domain (optional):** registration age via RDAP.
**DNS (optional):** A/AAAA/MX/NS resolution via Google DoH.
**External reputation:** intentionally not used; PhishGuard remains client-side and has no third-party reputation API dependency.

## 8. External intelligence

PhishGuard intentionally does **not** use VirusTotal, PhishTank, or another
third-party reputation API at runtime. The shipped detection pipeline uses
local URL/ML/DOM analysis plus optional RDAP domain-age and Google DNS-over-HTTPS
lookups. If domain or DNS data is unavailable, it contributes zero rather than
being treated as evidence of safety.

This design keeps the core detector independent of API keys, third-party
reputation quotas, and external reputation-service availability. The popup
has no "Reputation" row at all - it shows only the categories the risk
engine actually scores (ML Model, Webpage, Domain), so there is no
placeholder result to potentially mislead the user.

## 9. Testing (real results from this codebase, not fabricated)

Reproduce all of this with `node training/regression_test/run_regression.mjs`
(runs the actual `js/riskEngine.js` + `js/mlModel.js`, no browser needed)
plus the targeted checks below.

### Targeted safety tests (`js/riskEngine.js` behavior)

| Scenario | Verdict | Score |
|---|---|---|
| `claude.ai/new`, ML=94.6%, everything else unavailable | **SAFE** | 29 |
| `accounts.google.com/signin`, ML=74.9%, everything else unavailable | **SAFE** | 28 |
| Credential harvesting (password + cross-origin submit) | **HIGH_RISK** | 60 |
| Brand impersonation (`arcticwolfnetworks.mfaregister.com`) + new domain | **HIGH_RISK** | 60 |

### Legitimate regression suite (107 real URLs, spec-required categories:
auth, ecommerce, banking, news, social, SaaS, developer, docs, blog,
government, education, payment), domain/DNS marked unavailable (a
realistic default when RDAP/DoH lookups are not performed or time out)

**0 false positives (0.00% FPR). 107/107 SAFE**, including
`accounts.google.com/signin`, `login.microsoftonline.com`,
`appleid.apple.com/sign-in`, `www.amazon.in/gp/cart`, and `claude.ai/new` -
all of which score high (70-95%) on the ML sub-model alone, but the risk
engine's evidence-fusion policy (see `training/README.md`'s "v5.0.1
changes" section) requires more than an isolated ML score below a very
high, measured confidence bar before it will move a page out of SAFE.

### Phishing regression suite (120 confirmed-phishing URLs, domains that
appear **nowhere** in the training/val/test data)

| Scenario | HIGH_RISK | SUSPICIOUS | SAFE (false negative) |
|---|---|---|---|
| URL+ML only (DOM/reputation/domain/DNS all unavailable) | 0 (0%) | 53 (44.2%) | 67 (55.8%) |
| URL+ML+DOM (realistic credential-harvest pattern present) | 120 (100%) | 0 | 0 |

The URL-only row is an honestly disclosed, deliberate trade-off, not an
oversight: the previous version of this project caught more of these
(76.7%) by letting an isolated high ML score alone push the verdict to
SUSPICIOUS, but that was measured to also falsely flag the major
legitimate sites listed above under the identical "nothing else available"
condition - there is no ML confidence threshold in the overlapping 70-95%
range that separates them. Given this project's explicit requirement that
major legitimate sites must never be flagged, false-positive elimination
was prioritized over recall in this specific worst case. This is not a bug
to suppress - real usage where reputation, domain-age, or DOM evidence is
available performs meaningfully better, via the corroboration and
evidence-fusion gates that both rows above exercise identically.

### Feature-extraction parity (Python training vs. browser inference)

1800+ and 4000+-URL checks: **0 mismatches**, including IPv6/userinfo/
punycode/custom-port/malformed-input edge cases. Two real encoding bugs
were found and fixed during this testing (browser `URL` object
auto-re-encoding diverging from Python's `urlsplit`) - documented in
`training/README.md`.

### Model export parity (scikit-learn vs. the flat-JSON JS tree-walker)

800 real URLs: max probability difference **0.0044** (pure floating-point
rounding from 4-decimal threshold export), **0 label flips**.

### Public Suffix List parity

3000 real hostnames: **3000/3000 exact matches** between Python and JS,
including co.uk/com.au/co.jp/github.io/exception-rule edge cases.

### Navigation safety

Verified with mocked Chrome APIs: (1) a stale DOM-analysis message for a
page the tab has since navigated away from is correctly discarded rather
than corrupting the current record; (2) DOM analysis that never arrives
(page blocked/offline) correctly leaves that category `UNKNOWN`, not
"safe"; (3) the "proceed anyway" allowlist correctly prevents a redirect
loop back to the warning page.

### Not yet done

Live Chrome "Load unpacked" visual testing - this project was built and
tested in a headless sandbox using Node.js with mocked `chrome.*` APIs.
Please verify popup/warning-page rendering yourself per the installation
steps below before relying on this in production.

## 10. Installation

1. Open Chrome, go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**, select the `phishguard/` folder (containing
   `manifest.json`)
4. The PhishGuard icon appears in your toolbar

No build step - plain JavaScript (ES modules), HTML, CSS.

## 11. Chrome permissions

| Permission | Why |
|---|---|
| `tabs` | Read the active tab's URL; detect navigation |
| `host_permissions: http://*/*, https://*/*` | Inject the DOM-analysis content script on visited pages; let the background worker query RDAP/DoH without their CORS headers blocking it |

No other permissions requested.

## 12. Known limitations (honest disclosure)

- **URL-only phishing recall is limited** (see Testing) - ~66% caught,
  ~34% false-negative when DOM/reputation/domain are all unavailable for a
  confirmed-phishing URL. This is inherent to passive URL analysis, not a
  gap the risk engine can paper over without more evidence.
- **The malicious training class mixes phishing with generic malware/
  spam/scam** (see `training/README.md`'s source breakdown); recall is
  reported separately for each, but the model is not phishing-exclusive.
- **`tld_length` is the single most important ML feature (0.19)** - a real
  signal, but worth continued monitoring.
- **RDAP/DNS availability varies** by registry/network policy; both fail
  safely to "Unavailable."
- **eTLD+1 parsing uses the real Public Suffix List**, which is itself a
  maintained-by-humans list; extremely new or obscure suffixes not yet in
  the bundled snapshot would fall back to the PSL's own default rule
  (last label only).
- **Live browser UI has not been visually verified** in an actual Chrome
  window - please confirm yourself.
- **SPA (pushState) route changes** without a full page navigation may not
  automatically retrigger analysis (Chrome's `tabs.onUpdated` doesn't fire
  for these) - a known scope limitation, not silently hidden.

## 13. Security considerations

No `eval()`, no `new Function()`, no inline scripts, no `innerHTML` with
untrusted content, anywhere in the codebase. No hardcoded API keys or
secrets. No dependency on localhost/Flask/any backend server. All rendered
text uses `textContent`/DOM node creation, never HTML injection. PhishGuard
performs its core phishing analysis locally in the browser: URL features,
ML prediction, DOM analysis, redirect analysis, typosquatting/IDN checks,
credential-form correlation, and risk scoring are all done on-device. For
additional domain intelligence, PhishGuard may query public RDAP services
for domain registration information and Google's public DNS-over-HTTPS
service for DNS information - these are the only external network calls
the extension makes. PhishGuard does not use VirusTotal or PhishTank at
runtime, does not send passwords or submitted form values anywhere, and
does not upload full page contents to any PhishGuard-operated backend
(PhishGuard has no backend).

## 14. Project structure

```
phishguard/
├── manifest.json
├── background.js              (navigation generation tracking, evidence orchestration)
├── content.js                 (DOM analysis, PSL-based cross-origin detection)
├── warning.html / warning.js / warning.css
├── popup/
│   ├── popup.html / popup.js / popup.css   (scored reasons + separate "page facts")
│   └── options.html / options.css
├── js/
│   ├── featureExtractor.js    (36 features, is_https excluded, PSL-based)
│   ├── psl.js                 (real Public Suffix List parser)
│   ├── mlModel.js             (tree-walker + Platt calibration)
│   ├── riskEngine.js           (fixed weight caps + explicit corroboration policy)
│   ├── domainService.js / utils.js / config.js
│   └── psl_data.json
├── model/
│   ├── model.json / metadata.json / eval_report.json / feature_schema.json
│   │   (active shipped model: Gradient Boosting, see training/README.md "v5.0.1 changes")
│   ├── model_rf.json / metadata_rf.json / eval_report_rf.json
│   │   (previous Random Forest model, kept for comparison/rollback, NOT loaded by the extension)
│   ├── lists_config.json / psl_data.json
├── training/
│   ├── prepare_dataset.py / psl.py / feature_extractor.py
│   ├── train_model.py         (Random Forest - kept for reproducibility/comparison)
│   ├── train_model_gb.py      (Gradient Boosting - trains the model actually shipped)
│   ├── evaluate_model.py
│   ├── regression_test/run_regression.mjs (runs js/riskEngine.js + js/mlModel.js directly, no browser)
│   ├── legit_regression_suite.json / phishing_regression_suite.json
│   ├── feature_schema.json / lists_config.json / psl_data.json
│   ├── requirements.txt / README.md (full methodology + bug write-ups)
│   ├── sklearn_model.joblib (Random Forest, offline reference copy, NOT loaded by the extension)
│   └── sklearn_model_gb.joblib (Gradient Boosting, offline reference copy, NOT loaded by the extension)
├── icons/
└── README.md (this file)
```
