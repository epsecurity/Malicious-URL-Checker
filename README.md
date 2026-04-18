# Malicious URL Checker

Personal triage tool. Submit a URL from PowerShell (or a REST API call), GitHub
Actions runs a small multi-source intel pipeline, Claude reviews the evidence,
and you get back a short verdict plus key indicators. Purpose: fast first-pass
"is this worth sandboxing?" judgment — not a SOC-grade report.

```
URL → [validate] → [collect: urlscan, abuseipdb, gsb, whois, html]
                 → [pattern-scan] → [claude verdict] → [report]
```

Typical run time: 2–4 minutes (URLScan polling is the long pole).

---

## Setup

### 1. Get API keys (≈10 min)

| Service | Where |
|---|---|
| urlscan.io | https://urlscan.io → register → Profile → API Keys |
| AbuseIPDB | https://abuseipdb.com → register → Account → API |
| Google Safe Browsing | https://console.cloud.google.com → create project → enable **Safe Browsing API** → Credentials → API key |
| Anthropic | https://console.anthropic.com → API Keys |

All four are free-tier adequate for personal triage.

### 2. Create the GitHub repo

```bash
cd malicious-url-checker
gh repo create malicious-url-checker --private --source=. --remote=origin
git add .
git commit -m "initial scaffold"
git push -u origin main
```

### 3. Add the four secrets

Replace the placeholder values with your keys:

```bash
gh secret set URLSCAN_API_KEY    --body "..."
gh secret set ABUSEIPDB_API_KEY  --body "..."
gh secret set GSB_API_KEY        --body "..."
gh secret set ANTHROPIC_API_KEY  --body "..."
```

Or add them via the GitHub UI: **Settings → Secrets and variables → Actions → New repository secret**.

### 4. Create a fine-grained PAT (for PowerShell)

1. Go to https://github.com/settings/personal-access-tokens/new
2. **Repository access**: only this repo
3. **Permissions**:
   - *Contents*: **Read and write** (needed for `repository_dispatch`)
   - *Actions*: **Read** (needed to poll run status + download artifacts)
   - *Metadata*: **Read** (auto-granted)
4. Copy the generated token.

### 5. Install the PowerShell module

In PowerShell:

```powershell
$env:GH_DISPATCH_TOKEN = "ghp_xxxxx"        # the PAT you just made
$env:GH_REPO_OWNER     = "your-github-user"
$env:GH_REPO_NAME      = "malicious-url-checker"

Import-Module "C:\path\to\malicious-url-checker\powershell\Invoke-UrlScan.psm1"

Invoke-UrlScan -Url "https://example.com"
```

Add the env vars to your `$PROFILE` so they persist across sessions.

---

## Usage

### PowerShell

```powershell
# Basic — prints a colored summary to the terminal
Invoke-UrlScan -Url "https://suspicious.example"

# Also open the full HTML report in your browser
Invoke-UrlScan -Url "https://suspicious.example" -OpenReport

# JSON output (for piping / scripting)
Invoke-UrlScan -Url "https://suspicious.example" -Json | ConvertFrom-Json
```

### Manual (GitHub UI)

Go to **Actions → analyze-url → Run workflow**, paste a URL, click Run.
Download the artifact when it finishes.

### REST API (optional)

```bash
pip install -r requirements.txt
export GH_DISPATCH_TOKEN=...
export GH_REPO_OWNER=...
export GH_REPO_NAME=...
export API_TOKEN=$(openssl rand -hex 32)
uvicorn api.main:app --port 8080
```

```bash
curl -X POST http://localhost:8080/scan \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://suspicious.example"}'
# → 202 { "run_id": ..., "status_url": "/scan/12345", "run_url": "..." }

curl http://localhost:8080/scan/12345 -H "Authorization: Bearer $API_TOKEN"
# → { "status": "completed", "summary": { ... } }
```

---

## Terminal output example

```
URL Analysis: hxxps://login-micros0ft[.]ru

  Verdict:       SUSPICIOUS      Confidence: 0.82
  Action:        sandbox
  Summary:       Recently registered lookalike domain with credential form

  Key Indicators:
    - Domain registered 4 days ago (NiceNIC, RU)
    - Password input on HTTP form, action to .c2.su domain
    - URLScan tags: phishing, credential-harvest
    - AbuseIPDB: hosting IP has 87/100 abuse score

  Domain age:    4 days (NiceNIC)
  Hosting IP:    185.x.x.12   AbuseIPDB: 87/100
  URLScan:       https://urlscan.io/result/abc-123-def
  GHA run:       https://github.com/you/malicious-url-checker/actions/runs/...
```

---

## Project layout

```
.github/workflows/analyze-url.yml   # GHA orchestration
scripts/                            # one Python file per pipeline stage
rules/patterns.yml                  # YARA-style detection rules (tune freely)
prompts/system.md                   # Claude system prompt
powershell/Invoke-UrlScan.psm1      # PowerShell cmdlet
api/main.py                         # Optional FastAPI wrapper
```

All `scripts/collect_*.py` are independently runnable for local testing:

```bash
URLSCAN_API_KEY=xxx python scripts/collect_urlscan.py --url https://example.com
python scripts/collect_whois.py --url https://example.com
```

---

## Tuning

- **Pattern rules**: edit `rules/patterns.yml` and commit — no code changes.
- **Claude prompt**: edit `prompts/system.md`.
- **Model**: pinned to `claude-sonnet-4-6` in `scripts/claude_verdict.py`.

---

## Notes

- URLScan submissions use `visibility: unlisted` — URLs aren't published on
  the public feed but are still viewable if someone has the scan UUID.
  Upgrade to a paid urlscan account if you need `private` scans.
- The SSRF validator rejects RFC 1918 / loopback / link-local / cloud metadata
  IPs. You can't point this at internal infrastructure.
- Artifacts are retained for 30 days by default.
- PAT needs to be rotated every 90 days (or less, depending on your settings).
