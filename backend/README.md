# PhishGuard Web Risk backend

A minimal Node.js + Express service with one job: let the PhishGuard Chrome
extension check a URL against [Google Web Risk](https://docs.cloud.google.com/web-risk/docs/overview)
without the extension ever holding a Google API key. No database, no
accounts, no scan history - this is deliberately not more than that.

```
Chrome Extension  --HTTPS-->  This backend  --HTTPS-->  Google Web Risk Lookup API
```

## Endpoints

| Method | Path                  | Purpose                                    |
|--------|-----------------------|---------------------------------------------|
| GET    | `/health`              | Liveness check. Returns `{"status":"ok"}`. Never reveals config/secrets. |
| POST   | `/api/webrisk/check`   | Body `{"url": "https://example.com"}`. Returns the normalized three-state result (see below). |

### Response shape

```jsonc
// Match
{ "success": true,  "provider": "Google Web Risk", "matched": true,  "threatTypes": ["SOCIAL_ENGINEERING"], "expireTime": "2026-09-16T00:00:00Z", "checkedAt": "...", "error": null }
// No match
{ "success": true,  "provider": "Google Web Risk", "matched": false, "threatTypes": [], "expireTime": null, "checkedAt": "...", "error": null }
// Unavailable (timeout, network failure, invalid key, Google 5xx, rate limit, malformed input, ...)
{ "success": false, "provider": "Google Web Risk", "matched": false, "threatTypes": [], "expireTime": null, "checkedAt": "...", "error": "..." }
```

The extension (`js/webRiskClient.js`) treats **any** `success !== true` the
same way, regardless of cause: PhishGuard's own result stands unchanged.

## Local development

```bash
cd backend
npm install
cp .env.example .env
# edit .env and set GOOGLE_WEB_RISK_API_KEY=<your key>
npm start
```

Verify it's up:

```bash
curl http://localhost:8787/health
curl -X POST http://localhost:8787/api/webrisk/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Then, in the extension, open **PhishGuard → ⚙ Settings → PhishGuard backend
URL** and enter `http://localhost:8787`, click **Save**, then **Test
Connection** to confirm it's reachable.

## Getting a Google Web Risk API key

1. Create or select a project in the [Google Cloud Console](https://console.cloud.google.com/).
2. Enable **Web Risk API** for that project.
3. Create an API key (APIs & Services → Credentials) and **restrict it** to
   the Web Risk API only (API restrictions), so it can't be misused for
   other Google Cloud services if it ever leaks.
4. Put that key in `.env` as `GOOGLE_WEB_RISK_API_KEY` - never in the
   extension, never committed to source control.
5. Review current [Web Risk pricing](https://cloud.google.com/web-risk/pricing)
   and [quotas](https://docs.cloud.google.com/web-risk/quotas) - both may
   have changed since this file was written; check the live pages.

## Production deployment (Cloud Run is a natural fit - Web Risk is a Google
Cloud service - but any Node-capable HTTPS host works identically)

1. From `backend/`, build and deploy:
   ```bash
   gcloud run deploy phishguard-webrisk-backend \
     --source . \
     --region <your-region> \
     --allow-unauthenticated \
     --set-env-vars NODE_ENV=production,ALLOWED_ORIGINS=chrome-extension://<your-published-extension-id> \
     --set-secrets GOOGLE_WEB_RISK_API_KEY=phishguard-webrisk-key:latest
   ```
   (Store the real key in [Secret Manager](https://cloud.google.com/secret-manager)
   rather than as a plain `--set-env-vars` value - `--set-secrets` above
   assumes you've already created a secret named `phishguard-webrisk-key`.)
2. Cloud Run gives you an HTTPS URL like `https://phishguard-webrisk-backend-xxxxx.a.run.app`.
   Cloud Run terminates TLS for you - no separate certificate management needed.
3. You do **not** need to be a free-tier user forever, but Cloud Run's free
   tier (a fixed number of requests/CPU-seconds per month) is normally
   enough for a single-user or small-userbase extension; review current
   pricing before assuming that stays true at scale.

## Connecting the published extension to this backend

1. Confirm your Chrome Web Store extension ID (visible on the Developer
   Dashboard after your first upload, or in `chrome://extensions` in
   Developer Mode for a locally loaded build).
2. Set `ALLOWED_ORIGINS=chrome-extension://<that-id>` on the deployed
   backend and redeploy (or update the Cloud Run service's env var).
3. In the extension's Settings page, set the **PhishGuard backend URL** to
   your deployed HTTPS URL and click **Test Connection**.
4. This setting is per-install (stored in `chrome.storage.local`) - it is
   *not* baked into the extension package, so you can point different
   installs (or a future update) at different backends without rebuilding.

## What this backend deliberately does NOT do

- No database, no user accounts, no scan history (out of scope for this
  phase, by explicit project rule).
- No generic proxy - `/api/webrisk/check` only ever performs a Web Risk
  Lookup API call for the single URL in the request body.
- No other threat-intelligence provider (no VirusTotal, PhishTank, Safe
  Browsing API v4, etc.) - Web Risk Lookup API only.
- Never returns, logs to a client-visible place, or otherwise exposes
  `GOOGLE_WEB_RISK_API_KEY`.
