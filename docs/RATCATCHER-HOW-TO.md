# Access Compliance Engine — Ops & Recovery How-To

**Last updated:** April 2026  
**Author:** Mark Berry  
**Purpose:** Everything you (or Claude Code) need to understand, maintain, and restore the Access Compliance Engine (ACE) from scratch. (Repository name, file paths, env var names, URLs, and code identifiers still use the legacy "RatCatcher" / "ratcatcher" naming — those are paths, not product branding, and are deliberately out of scope for the cosmetic rebrand.)

---

## What Is the Access Compliance Engine?

The Access Compliance Engine (ACE) is a **PowerShell forensic scanner suite** built to detect evidence of npm supply-chain compromises — initially the March 31, 2026 Axios NPM supply chain attack, now extended to the Mini Shai-Hulud worm campaign (via the sibling WormCatcher scanner). It consists of two main parts:

1. **The Scanner** — a PowerShell script (`Invoke-RatCatcher.ps1` for the Axios campaign; `Invoke-MiniShaiHulud.ps1` for the Mini Shai-Hulud campaign) that employees run on their machines. Each runs a series of checks, generates HTML reports, and submits results to the dashboard.
2. **The Dashboard** — a Cloudflare Worker that receives scan submissions, stores them, runs AI verdict analysis, and provides a web UI for the security team to review results.

The live dashboard is at: **https://mbfromit.com/ratcatcher/dashboard**

---

## Where Everything Lives

### Source Code
```
/Users/mberry/Documents/ClaudeProjects/RatCatcher/
├── Invoke-RatCatcher.ps1           # Main scanner entry point (distributed to employees)
├── Private/                        # Scanner modules (10 check functions)
│   ├── Find-ForensicArtifacts.ps1
│   ├── Find-PersistenceArtifacts.ps1
│   ├── Get-NetworkEvidence.ps1
│   ├── Get-NodeProjects.ps1
│   ├── Invoke-LockfileAnalysis.ps1
│   ├── Invoke-NpmCacheScan.ps1
│   ├── New-ExecBriefing.ps1
│   ├── New-ScanLogHtml.ps1
│   ├── New-ScanReport.ps1
│   ├── Search-DroppedPayloads.ps1
│   ├── Search-XorEncodedC2.ps1
│   ├── Send-ScanReport.ps1
│   └── Submit-ScanToApi.ps1
├── cloudflare/                     # Cloudflare Worker (the dashboard + API)
│   ├── wrangler.toml               # Cloudflare deployment config
│   ├── schema.sql                  # D1 database schema
│   └── src/
│       ├── index.js                # Worker entry point + routing
│       ├── util.js                 # Auth helper (checkAdminPassword)
│       └── handlers/
│           ├── api.js              # Stats, submissions, report serving
│           ├── ai-verify.js        # Gemma AI verdict logic
│           ├── ack.js              # Finding acknowledgement (certify/false-positive)
│           ├── dashboard.js        # Dashboard HTML/JS
│           ├── submit.js           # Scan submission handler
│           └── userReport.js       # Per-user report handler
├── Tests/                          # Pester unit tests for scanner
├── TestArtifacts/                  # PowerShell scripts to plant synthetic IOCs for testing
├── docs/                           # Documentation (you are here)
└── ratcatcher-db-backup-*.sql      # D1 database exports (keep these safe)
```

### Cloudflare (Production Infrastructure)
| Resource | Type | Name / ID |
|---|---|---|
| Worker | Cloudflare Worker | `ratcatcher` |
| Database | D1 (SQLite) | `ratcatcher` — ID: `b535d898-8007-4fc8-8f41-63da8dd1f1a3` |
| Reports storage | R2 bucket | `ratcatcher-reports` |
| Route | DNS | `mbfromit.com/ratcatcher/*` |
| Cron | Worker trigger | `*/5 * * * *` (auto-evaluates new COMPROMISED submissions) |
| Cloudflare Account | Login | `mbfromit@gmail.com` |

### Dev Environment (Cloudflare)
| Resource | Type | Name / ID |
|---|---|---|
| Worker | Cloudflare Worker | `ratcatcher-dev` |
| Database | D1 (SQLite) | `ratcatcher-dev` — ID: `90e9640b-afe2-4e81-9734-b1a0731b5e91` |
| Reports storage | R2 bucket | `ratcatcher-dev-reports` |
| Route | DNS | `mbfromit.com/ratcatcher-dev/*` |

### Credentials
All secrets are stored in **`/Users/mberry/.claude/.env`**.

Key variables:
- `RATCATCHER_ADMIN_PASSWORD` — the admin password for the dashboard web UI **and** the submission password employees enter when running the scanner. Same value for both.
- `CLOUDFLARE_KEY` — Cloudflare API key (used by wrangler for deployments).

The Worker also has two **Cloudflare-side secrets** (set via `wrangler secret`):
- `ADMIN_PASSWORD` — must match `RATCATCHER_ADMIN_PASSWORD` above.
- `AI_TUNNEL_URL` — URL of the Cloudflare Tunnel to the Ollama/Gemma AI instance (see AI section below).
- `AI_API_KEY` — API key for the AI tunnel.

> **Note:** The Worker secrets are stored in Cloudflare, not locally. To view or update them: Cloudflare Dashboard → Workers → ratcatcher → Settings → Variables & Secrets.

---

## How the Dashboard Works

The dashboard is a **single Cloudflare Worker** (`src/index.js`) that handles everything:

- `GET /ratcatcher/dashboard` → serves the dashboard HTML (requires X-Admin-Password header or prompt)
- `POST /ratcatcher/submit` → receives scan submissions from the PowerShell scanner
- `GET /api/stats` → JSON stats for the dashboard filter cards
- `GET /api/submissions` → paginated submission list with filtering
- `GET /api/report/:id` → serves stored HTML report from R2
- `POST /api/submissions/:id/ai-verify` → triggers AI verdict for one submission
- `POST /api/ai-verify-all` → bulk AI evaluation (also triggered by the `*/5 * * * *` cron)
- `GET /api/ai-status` → checks if Gemma model is loaded
- Various `/api/submissions/:id/ack` routes for finding acknowledgements

### Dashboard Filter Cards (what each one counts)
All cards reflect the **most recent scan per hostname** (fleet state), not historical totals.

| Card | What it shows |
|---|---|
| **Total Scans** | All rows ever submitted |
| **Unique Scans** | COUNT DISTINCT hostnames (one per machine, latest scan) |
| **Clean** | Latest scan per host = CLEAN |
| **Positive Findings** | Latest scan = COMPROMISED + not reviewed/false-positived |
| **Unreviewed** | Latest scan = COMPROMISED + not reviewed (matches Positive Findings) |
| **Remediated** | Machines that were previously COMPROMISED but latest scan = CLEAN, OR were reviewed/certified after compromise |
| **Reviewed** | Submissions that have been manually certified or false-positived |

---

## How to Deploy (after code changes)

All deployments go through **wrangler** from the `cloudflare/` directory.

```bash
cd /Users/mberry/Documents/ClaudeProjects/RatCatcher/cloudflare

# Deploy to production
npx wrangler deploy

# Deploy to dev environment
npx wrangler deploy --env dev
```

That's it. No pipeline — just push via wrangler directly. The Worker is live within seconds.

**Before deploying**, run tests:
```bash
cd /Users/mberry/Documents/ClaudeProjects/RatCatcher/cloudflare
npm test
```

---

## How to Restore from Backup

### Scenario: Worker code is broken or accidentally deleted

```bash
cd /Users/mberry/Documents/ClaudeProjects/RatCatcher/cloudflare
npx wrangler deploy
```

That re-deploys everything from the source code in this repo.

### Scenario: D1 database is lost or corrupted

A SQL backup is kept at:
```
/Users/mberry/Documents/ClaudeProjects/RatCatcher/ratcatcher-db-backup-YYYYMMDD-HHMMSS.sql
```

To restore:
```bash
cd /Users/mberry/Documents/ClaudeProjects/RatCatcher/cloudflare

# Restore to production DB
npx wrangler d1 execute ratcatcher --file=../ratcatcher-db-backup-20260413-113526.sql --remote

# If you need to recreate the DB schema first (empty DB):
npx wrangler d1 execute ratcatcher --file=schema.sql --remote
```

### Scenario: Worker secrets are gone (e.g. account reset)

Re-set them via wrangler:
```bash
# You'll be prompted to enter the value
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put AI_TUNNEL_URL
npx wrangler secret put AI_API_KEY
```

Values are in `/Users/mberry/.claude/.env`.

### Scenario: Full DR — starting from zero on a fresh Cloudflare account

1. Create D1 databases: `npx wrangler d1 create ratcatcher` and `npx wrangler d1 create ratcatcher-dev`
2. Update the database IDs in `wrangler.toml` with the new IDs from step 1
3. Apply schema: `npx wrangler d1 execute ratcatcher --file=schema.sql --remote`
4. Restore data from backup SQL file (see above)
5. Create R2 buckets: `npx wrangler r2 bucket create ratcatcher-reports` and `ratcatcher-dev-reports`
6. Set secrets: `ADMIN_PASSWORD`, `AI_TUNNEL_URL`, `AI_API_KEY`
7. Deploy: `npx wrangler deploy`

---

## AI Verification (Gemma) — Current Status: OFFLINE

ACE uses **Gemma 4 (31B)** running via **Ollama** to automatically evaluate each finding and return a verdict (Confirmed / Likely / Unlikely / FalsePositive).

### Architecture
```
Cloudflare Worker  →  Cloudflare Tunnel  →  AWS instance running Ollama + Gemma 4 31B
```

The Worker calls `env.AI_TUNNEL_URL` (the tunnel URL) with an API key (`env.AI_API_KEY`).

### Current State
The AWS Gemma instance was **intentionally shut down in April 2026** — the incident response is complete. The Worker handles this gracefully: if `AI_TUNNEL_URL` is not set or the model is unreachable, all AI features return a 503 and the dashboard's AI buttons are non-functional. Everything else (dashboard, submissions, manual review) works normally.

**Existing AI verdicts in the database are preserved** — they don't disappear when the model goes offline.

### To Re-enable AI (if needed for a future incident)

1. Spin up an AWS instance with enough VRAM for Gemma 4 31B (~24GB minimum)
2. Install Ollama: https://ollama.com — then `ollama pull gemma4:31b`
3. Create a Cloudflare Tunnel to the instance exposing port 11434 (Ollama's default)
4. Set up an API key on the tunnel for authentication
5. Update Cloudflare Worker secrets:
   ```bash
   npx wrangler secret put AI_TUNNEL_URL   # e.g. https://your-tunnel.cfargotunnel.com
   npx wrangler secret put AI_API_KEY      # your tunnel API key
   ```
6. Test via the dashboard → any COMPROMISED submission → click "Re-Evaluate"

---

## Database Schema (Quick Reference)

Key tables in D1:

| Table | Purpose |
|---|---|
| `submissions` | One row per scan. Columns: `id`, `hostname`, `username`, `submitted_at`, `verdict` (CLEAN/COMPROMISED), `ai_verdict`, `findings_count`, `report_key` (R2 key), `reviewed` |
| `finding_acknowledgements` | Manager certifications and false-positive overrides per finding |
| `finding_ai_verdicts` | Per-finding AI verdict detail (verdict, reason, category) |

To export the live database at any time:
```bash
cd /Users/mberry/Documents/ClaudeProjects/RatCatcher/cloudflare
npx wrangler d1 export ratcatcher --remote --output=../ratcatcher-db-backup-$(date +%Y%m%d-%H%M%S).sql
```

---

## What to Tell Claude Code

If starting a fresh session, give Claude Code this prompt to get it up to speed instantly:

---

> **Context for Claude Code:**
>
> I need help with the **Access Compliance Engine** (ACE — internal repo / code identifiers still use the legacy "RatCatcher" name), a PowerShell security scanner suite with a Cloudflare Worker dashboard.
>
> **Source code:** `/Users/mberry/Documents/ClaudeProjects/RatCatcher/`
>
> **Key files:**
> - `Invoke-RatCatcher.ps1` — PowerShell scanner (runs on employee machines)
> - `cloudflare/src/handlers/api.js` — dashboard API (stats, submissions, report serving)
> - `cloudflare/src/handlers/dashboard.js` — dashboard HTML/JS frontend
> - `cloudflare/src/handlers/ai-verify.js` — Gemma AI verdict logic
> - `cloudflare/wrangler.toml` — deployment config (D1 + R2 bindings, routes, cron)
> - `cloudflare/schema.sql` — D1 database schema
> - `docs/RATCATCHER-HOW-TO.md` — full architecture reference
>
> **Credentials:** `/Users/mberry/.claude/.env` contains `RATCATCHER_ADMIN_PASSWORD` and `CLOUDFLARE_KEY`.
>
> **Deploy:** `cd cloudflare && npx wrangler deploy` (no pipeline — direct wrangler push).
>
> **Live URL:** https://mbfromit.com/ratcatcher/dashboard
>
> The AI (Gemma) is currently **offline** — the AWS instance was shut down after the incident response was complete. The Worker handles this gracefully.

---

## Useful Commands Cheat Sheet

```bash
# Navigate to project
cd /Users/mberry/Documents/ClaudeProjects/RatCatcher

# Run tests
cd cloudflare && npm test

# Deploy to production
cd cloudflare && npx wrangler deploy

# Deploy to dev
cd cloudflare && npx wrangler deploy --env dev

# Export database backup
cd cloudflare && npx wrangler d1 export ratcatcher --remote --output=../ratcatcher-db-backup-$(date +%Y%m%d-%H%M%S).sql

# Check Worker logs (tail)
cd cloudflare && npx wrangler tail

# List D1 tables
cd cloudflare && npx wrangler d1 execute ratcatcher --command="SELECT name FROM sqlite_master WHERE type='table'" --remote

# Query submission count
cd cloudflare && npx wrangler d1 execute ratcatcher --command="SELECT COUNT(*) FROM submissions" --remote

# Check Worker secrets (lists names only, not values)
cd cloudflare && npx wrangler secret list
```

---

## Timeline Reference

| Date | Event |
|---|---|
| March 31, 2026 | Axios NPM supply chain attack — malicious `plain-crypto-js@4.2.1` distributed |
| April 2026 | Access Compliance Engine (then known as RatCatcher) built and deployed; fleet-wide scanning completed |
| April 2026 | AI verification (Gemma 4 31B on AWS) brought online for automated triage |
| April 13, 2026 | AWS Gemma instance shut down (incident response complete); DB backed up |
| 3 months later | You are reading this |
