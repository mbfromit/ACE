# PLAN — WormCatcher actionable per-finding verdicts (npm-audit driven)

**Status:** ready to implement
**Branch:** `feature/wormcatcher-bounded-detection` (continuation — same branch, additional commits)
**Owner:** next session
**Created:** 2026-05-21
**Supersedes nothing.** Builds on the bounded-detection plan; uses its discovery + Tier-1 work as foundation.

---

## Tool goal (frozen — restated from prior plan, unchanged)

> RatCatcher / WormCatcher is a forensics tool that, when run on a workstation, gives a high-confidence belief that this machine **either does or does not carry the specific vulnerability being scanned for**.

That goal was *partly* met by the bounded-detection branch (discovery walk + Tier-1 IOC probes), but a real-box E2E exposed a new failure mode: **the IOC bundle's scope wildcards (`@tanstack/*`, `@antv/*`, etc.) flag every version of every package in those scopes as compromised, producing 60+ false-positive Criticals on a single legitimate React project.** That undermines the "high-confidence belief" claim from the manager's perspective — the report drowns in noise and a manager triaging it can't tell signal from noise without running `npm audit` themselves.

This plan adds the **authoritative triage step inside the scanner**, so the result the manager sees is already post-triage.

---

## Why this plan exists (the 2026-05-21 turn-3 evidence)

A real E2E scan against the dev dashboard with three planted Tier-1 IOCs and the user's actual codebase produced **97 findings: 65 Critical, 31 High**. Manual investigation showed:

- **3 of the 65 Criticals were real** (the three Tier-1 plants — workflow file, payload, dropper, all at `C:\WormcatcherE2ETest\`)
- **62 of the 65 were false positives** — `@tanstack/react-query`, `@tanstack/react-table`, etc. flagged by wildcard scope match against `@tanstack/*` in the IOC bundle. Manual triage confirmed:
  - `npm audit` returned no advisories for these versions
  - Lockfile mtime (2026-04-15) predates the May 11, 2026 TanStack compromise wave by 26 days
  - Zero Tier-1 worm artifacts present at those project roots
- The remaining 31 High findings were corroborating noise (token atime in attack window, npm cache log writes) — also pre-existing.

Manager looking at this report without that manual investigation cannot tell which of the 65 Criticals is real and which are wildcard noise. The user's explicit goal from this turn: **give the manager the same authoritative power**, baked into the scanner so they don't have to do the forensics themselves.

---

## Product principles (frozen — do not redesign)

1. **The scanner emits manager-actionable verdicts, not raw IOC dumps.** Every finding the scanner produces gets a plain-English verdict the manager can act on without being a security analyst.

2. **The scanner's verdict cites the authority that produced it.** Not "Likely false positive — trust me" but "npm advisory DB does not flag this version + lockfile predates attack window — verified false positive."

3. **When the scanner cannot conclude, it says what the USER must do to enable it to conclude.** Manager forwards a pre-written instruction to the user; user complies; scanner re-runs and resolves.

4. **The full evidence is preserved in the database.** Cleared findings still exist as records — manager can drill down into history if a future investigation needs it. Only the *headline* changes; the *log* is complete.

5. **The headline reflects post-triage reality, not raw IOC-match counts.** A scan with 62 wildcard matches all cleared by npm audit reports as CLEAN, not COMPROMISED. The number `62` shows up in the headline so the manager understands what happened ("62 watchlist matches investigated, all 62 cleared by npm advisory DB").

---

## Design

### Phase A — Per-finding verdict + reason

Every finding the scanner produces gains four new fields in its `Extra` block:

```
ScannerVerdict       (string)  : Confirmed | Cleared | Inconclusive
ScannerVerdictReason (string)  : plain-English sentence the manager reads
ActionRequired       (string?) : null when verdict is decisive; otherwise the
                                 copy-paste instruction the manager forwards
ActionTarget         (string?) : null when no action; otherwise: User | Manager | Ops
```

Plus three lower-level corroborating fields the dashboard renders under a "Technical details" disclosure:

```
MatchedViaWildcard   (bool)    : did the IOC entry use scope wildcard like @tanstack/*
LockfileMtime        (datetime): when the lockfile was last touched
LockfileBeforeAttackWindow (bool) : did the lockfile predate attack_window_start
AuditResult          (string)  : npm-not-installed | network-error | no-lockfile |
                                 corrupted-lockfile | audit-clean | audit-flagged |
                                 not-applicable
```

### Phase B — `Invoke-MshNpmAudit` helper

New file `Private/MiniShaiHulud/Invoke-MshNpmAudit.ps1`. Wraps `npm audit --json` against a Node project root, parses the result, and returns a structured object the calling helper consumes:

```
[PSCustomObject]@{
    Concurs       = $true | $false | $null       # null = audit didn't run
    AuditResult   = '<one of the constants above>'
    Advisories    = @[ { package, version, severity, url } ]
    ErrorDetail   = $null | '<human-readable failure reason>'
    DurationMs    = <int>
}
```

Failure-mode detection — the helper must distinguish:

| Detection | `AuditResult` | When `Concurs` |
|---|---|---|
| `npm.exe` not on PATH or `Get-Command npm` fails | `npm-not-installed` | `$null` |
| `npm audit --json` exits 0 with `auditReportVersion >= 2` and no advisories for the queried package | `audit-clean` | `$false` |
| `npm audit --json` returns advisories matching the queried package@version | `audit-flagged` | `$true` |
| `npm audit` exits with network error stderr ('ENOTFOUND', 'ETIMEDOUT', 'ECONNREFUSED') | `network-error` | `$null` |
| `npm audit` exits with lockfile error ('lockfile missing', 'lockfile corrupt') | `no-lockfile` or `corrupted-lockfile` | `$null` |
| Other failure | `audit-failed` | `$null` |

Timeout: `npm audit` calls bound by **30 seconds** per project (parameter on the helper, default 30s). Hitting the timeout = `network-error` from the manager's perspective ("ask user to retry on better network").

### Phase C — `Find-MshBadPackages.ps1` enrichment

For every BadPackage-* finding the existing code emits, call `Invoke-MshNpmAudit` and embed:

- `ScannerVerdict` per the decision table below
- `ScannerVerdictReason` per the lookup table below
- `ActionRequired` (when applicable) per the lookup table below

**Decision table:**

| Match type | Audit result | Lockfile mtime | Verdict |
|---|---|---|---|
| Exact name+version pinned in IOCs | `audit-flagged` | any | **Confirmed** |
| Exact name+version pinned in IOCs | `audit-clean` | any | **Inconclusive** (contradiction between feed and audit — needs manual review) |
| Exact name+version pinned in IOCs | npm-not-installed / network-error / no-lockfile | any | **Inconclusive** (action required) |
| Wildcard scope match (e.g. `@tanstack/*`) | `audit-flagged` | any | **Confirmed** |
| Wildcard scope match | `audit-clean` | any | **Cleared** |
| Wildcard scope match | npm-not-installed / network-error / no-lockfile / corrupted-lockfile | before attack window | **Likely cleared** (action required if user wants definitive) |
| Wildcard scope match | npm-not-installed / network-error / no-lockfile / corrupted-lockfile | inside attack window | **Inconclusive** (action required) |

### Phase D — Per-finding ActionRequired catalog

Verbatim text per scenario. Manager copy-pastes; no editing needed.

| `AuditResult` | `ActionTarget` | `ActionRequired` text |
|---|---|---|
| `npm-not-installed` | User | "Install Node.js + npm from https://nodejs.org/en/download/, then re-run WormCatcher. The advisory check for this finding requires npm to be installed on this workstation." |
| `network-error` | User | "Confirm your workstation can reach the npm registry. From PowerShell, run: `Invoke-WebRequest https://registry.npmjs.org/`. If it fails, contact IT for npm registry firewall/proxy access. Then re-run the scanner." |
| `no-lockfile` | User | "Open PowerShell at `<PROJECT_ROOT>` and run `npm install` to generate package-lock.json. WormCatcher needs the lockfile to verify whether the flagged packages are actually compromised. Then re-run the scanner." |
| `corrupted-lockfile` | User | "The lockfile at `<PROJECT_ROOT>\package-lock.json` is corrupted. Delete it AND the `node_modules\` folder, then run `npm install` to rebuild. Then re-run the scanner. (Keep a backup of the deleted lockfile first if you need to preserve exact versions.)" |
| `audit-flagged` (Confirmed compromise) | User + Manager | "Compromise confirmed by npm advisory database. Begin incident response per [WormCatcher runbook](docs/MINI-SHAI-HULUD-RUNBOOK.md). Rotate npm tokens (`npm token list` / `npm token revoke <id>`) and any cloud credentials touched on this workstation since 2026-04-01." |
| `audit-clean` (Cleared) | — | (null — no action required) |
| Tier-1 hit (WormWorkflowFile, WormPayloadFile, WormDropperArtifact, TrufflehogDrop in attack window) | User + Manager | "Worm-specific artifact present on disk. IMMEDIATELY isolate this workstation from the network. Follow incident response in [WormCatcher runbook](docs/MINI-SHAI-HULUD-RUNBOOK.md): rotate all credentials, audit CI workflows, check git history for unauthorized commits." |
| TruffleHog drop outside attack window | Manager | "TruffleHog binary at unusual path but mtime predates the campaign attack window. Could be a legitimate developer install at a non-default location. Ask user: 'Did you install TruffleHog at `<PATH>` yourself?' If no, escalate." |

Project-root path substitution (`<PROJECT_ROOT>`) is done at finding-emission time so each finding's ActionRequired is fully resolved — manager doesn't have to fill in blanks.

### Phase E — Overall scan verdict rollup

The four existing states (`COMPROMISED`, `REVIEW`, `CLEAN`, `INCONCLUSIVE`) stay. Their *trigger conditions* change to consume per-finding `ScannerVerdict`:

| Triggering condition | Overall verdict |
|---|---|
| Any finding with `ScannerVerdict = Confirmed` | **COMPROMISED** |
| Zero `Confirmed`, ≥1 `Inconclusive` with `ActionRequired` from user | **REVIEW** (manager needs to chase users) |
| Zero `Confirmed`, all findings either `Cleared` or have non-blocking `Inconclusive` reasoning | **CLEAN** (with audit-count summary in the headline) |
| Zero roots discovered AND no `-Path` supplied | **INCONCLUSIVE** (unchanged from prior plan) |

### Phase F — Headline rewrite (technical report + brief)

Header line on both reports stops saying "Verdict: COMPROMISED (findings: 97; Critical: 65; High: 31)" and starts saying:

**For COMPROMISED:**
> COMPROMISED — 3 confirmed Tier-1 worm artifacts (workflow file at `<path>`, payload at `<path>`, dropper at `<path>`). 62 additional watchlist matches investigated by npm advisory database; all 62 cleared. 31 corroborating signals (token atime, npm cache activity).

**For CLEAN (real example from today's box, post-triage):**
> CLEAN — 62 watchlist matches investigated by npm advisory database; all 62 cleared (no advisories for those exact versions). 0 Tier-1 worm artifacts present. 31 corroborating signals reviewed.

**For REVIEW (some findings need user action):**
> REVIEW — 3 findings could not be verified by npm advisory database (npm not installed on this workstation). 62 watchlist matches investigated; 62 cleared. 0 Tier-1 worm artifacts. Forward the per-finding `ActionRequired` instructions to the affected users to complete triage.

### Phase G — Brief's "Action items" aggregation

New section in the exec briefing, **grouped by user/host**. Replaces / sits above the existing per-finding listing.

```
ACTION ITEMS — 1 user(s) need to perform setup before triage can complete

╔══════════════════════════════════════════════════════════════════════╗
║ mberry @ AXDALCELAP4412 — 5 findings blocked                         ║
║                                                                       ║
║ Required action: Install Node.js + npm from                          ║
║                  https://nodejs.org/en/download/, then re-run         ║
║                  WormCatcher.                                         ║
║                                                                       ║
║ Affected findings (5):                                                ║
║   • C:\Repos\app-a (BadPackage-Lockfile, @tanstack/react-query)      ║
║   • C:\Repos\app-b (BadPackage-Lockfile, @antv/g6)                   ║
║   • ...                                                               ║
║                                                                       ║
║ [Copy instruction to clipboard]   [Mark as forwarded]                ║
╚══════════════════════════════════════════════════════════════════════╝
```

Aggregation logic: for each unique `(hostname, username, ActionRequired)` tuple, emit one card. Cards sorted by number-of-blocked-findings descending so the highest-leverage actions appear first.

---

## Files to change

### New files

- `Private/MiniShaiHulud/Invoke-MshNpmAudit.ps1` — Phase B helper (~120 lines)
- `Tests/MiniShaiHulud/Invoke-MshNpmAudit.Tests.ps1` — Pester for all failure modes

### Modified files

- `Private/MiniShaiHulud/Find-MshBadPackages.ps1` — Phase C verdict enrichment, downgrade wildcard matches to HIGH (~80 lines added)
- `Private/MiniShaiHulud/Find-MshWormWorkflow.ps1` — embed static `Confirmed` verdict + Tier-1 ActionRequired (~10 lines)
- `Private/MiniShaiHulud/Find-MshPayloadFile.ps1` — same (~10 lines)
- `Private/MiniShaiHulud/Find-MshDropperArtifact.ps1` — same (~10 lines)
- `Private/MiniShaiHulud/Find-MshTrufflehogDrop.ps1` — same (~15 lines — has in/out-of-window split)
- `Invoke-MiniShaiHulud.ps1` — Phase E verdict rollup change, add `-SkipNpmAudit` parameter (default OFF), thread audit results into `$meta` (~30 lines)
- `Private/MiniShaiHulud/New-MshScanReport.ps1` — Phase F headline rewrite + render `ScannerVerdict` chip on each finding (~40 lines)
- `Private/MiniShaiHulud/New-MshExecBriefing.ps1` — Phase F+G headline + action-items aggregation section (~60 lines)
- `README.md` — document `-SkipNpmAudit`, new verdict semantics, manager workflow (~30 lines)

### Plus the previously-greenlit items (still owed)

- `Private/MiniShaiHulud/Find-MshSuspiciousScripts.ps1` — fix the `$null.Name` StrictMode bug exposed by the wider discovery scope (52 projects errored on this turn's real-box E2E)
- `Verify-MshAcceptance.ps1` — extend with new test cases:
  - Wildcard match with audit-clean → verdict Cleared, no ActionRequired
  - Wildcard match with no-lockfile → verdict Inconclusive, ActionRequired set
  - Tier-1 plant with corroborating wildcard noise → headline correctly says "3 confirmed, 62 cleared" not "65 critical"
- Cleanup `C:\WormcatcherE2ETest\` plants once everything is validated

---

## Acceptance criteria

### Goal 1 — actionable verdicts

- [ ] **Wildcard-noise test:** plant `@tanstack/react-query@5.99.0` in a project, run scanner. Result: finding has `ScannerVerdict = Cleared`, severity HIGH (not Critical), `ActionRequired = null`, `ScannerVerdictReason` cites npm audit.
- [ ] **Exact-pinned-with-audit-flag test:** plant `mbt@1.2.48` (a real IOC entry) in a project with a fake npm audit hook that returns a flag. Result: `ScannerVerdict = Confirmed`, severity Critical, `ActionRequired` references the runbook.
- [ ] **Tier-1 test:** plant `shai-hulud-workflow.yml`. Result: `ScannerVerdict = Confirmed`, `ActionRequired` includes "isolate workstation immediately".
- [ ] **npm-not-installed test:** mock `Get-Command npm` to return null. Plant a wildcard finding. Result: `ScannerVerdict = Inconclusive`, `ActionRequired` is the verbatim npm-install instruction.
- [ ] **Manager workflow test:** brief renders "Action items" section grouped by (hostname, ActionRequired), one card per group, with copy-to-clipboard button text present in the HTML.

### Goal 2 — headline reflects post-triage reality

- [ ] **Mixed-findings test:** plant 3 Tier-1 hits + 60 wildcard matches (the today's-real-box scenario). Result: headline reads "COMPROMISED — 3 confirmed Tier-1 worm artifacts. 60 additional watchlist matches cleared by npm advisory DB."
- [ ] **All-cleared test:** plant 60 wildcard matches with no Tier-1. Result: headline reads "CLEAN — 60 watchlist matches investigated, all 60 cleared by npm advisory DB. 0 Tier-1 worm artifacts."

### Goal 3 — performance

- [ ] **Scan budget:** with `npm audit` running on the ~8 wildcard-matched projects from today's E2E, total scan stays under **5 minutes** (today's baseline was 2:32; budget allows +2:28 for audits).
- [ ] **`-SkipNpmAudit`:** flag honored; when set, wildcard findings stay Inconclusive with reason "audit skipped by operator." No regression in scan time.

### Goal 4 — regression

- [ ] All 45 existing Pester tests still green.
- [ ] `Verify-MshAcceptance.ps1` still 9/9 PASS on Windows (with the new acceptance cases added on top).
- [ ] Real-box E2E re-run against dev dashboard produces a fundamentally different (and accurate) headline compared to today's submission `32745acc-c644-4692-98ef-f3e53529df0b`.

---

## Suggested commit sequence

1. **`feat: Invoke-MshNpmAudit helper + tests`** — Phase B, isolated. Helper + Pester. No call sites yet.
2. **`feat: per-finding ScannerVerdict + ActionRequired (BadPackage path)`** — Phase A + C + D for BadPackage findings only. Existing Critical severity preserved for compatibility; verdict drives the new fields.
3. **`feat: wildcard matches downgrade to HIGH + finding description fix`** — severity change + description rewrite to not lie about "known compromised." This is the user-visible noise-reduction commit.
4. **`feat: Tier-1 findings emit Confirmed verdict + IR ActionRequired`** — Phase A applied to the four Tier-1 helpers. Static verdicts; no audit needed.
5. **`feat: scan verdict rollup consumes per-finding ScannerVerdict`** — Phase E. Updates `Invoke-MiniShaiHulud.ps1` so COMPROMISED requires at least one Confirmed.
6. **`feat: report headlines + brief action-items aggregation`** — Phase F + G. Updates both report templates.
7. **`fix: Find-MshSuspiciousScripts $null.Name bug under StrictMode`** — the pre-existing bug the wide discovery scope exposed. Independent fix.
8. **`docs: README updates for -SkipNpmAudit + manager workflow`** — documentation pass.
9. **`test: Verify-MshAcceptance new cases for verdict/ActionRequired flows`** — extends the acceptance suite.
10. **`chore: clean up C:\WormcatcherE2ETest\ plants`** — only if the user wants the script-managed cleanup; otherwise a manual `Remove-Item` after final validation.

---

## Open questions to resolve before implementing

1. **`npm` binary detection on macOS / Linux** — `Get-Command npm` works cross-platform under PS7, but homebrew npm may not be on PATH in non-interactive shells. Confirm the detection works on the Mac validation box.
2. **`npm audit --json` schema stability** — the audit JSON schema has changed between npm versions (v6 vs v7+). Pin to `auditReportVersion: 2` and document the minimum supported npm version (npm 7+ ships with Node 15+, so practically every dev box).
3. **`yarn audit` / `pnpm audit` fallback** — out of scope for this PR (npm only). Document as follow-up. Some projects in the wild are pnpm-only; for now those will get `AuditResult: no-lockfile` if package-lock.json is missing, which routes to the right `ActionRequired`.

---

## Rollback

This branch already has 9 commits on top of `main` (the bounded-detection work + Verify-MshAcceptance). The verdict/ActionRequired work adds another 8-10 commits on the same branch. Rollback paths:

- **Full revert:** `git reset --hard origin/main` discards the entire branch. The PR has not been opened yet, so this is safe.
- **Verdict-only revert:** revert just commits 10-18 (the new ones from this plan), keeping the bounded-detection work intact. Useful if the verdict scope reveals problems but the discovery work is solid.

The IOC feed schema (v1 → v2) and Worker changes from the bounded-detection branch are **forward-compatible**, so even a partial deploy is recoverable: scanners on the new branch handle absent fields, scanners on `main` ignore the new fields.

---

## What this plan does NOT do (deferred follow-ups)

These were discussed in the design conversation and intentionally pushed to separate PRs after this one ships:

- **Tier 2 — Worker-side npm advisory DB cross-reference.** The Worker would periodically pull the GitHub Security Advisory feed into D1 and cross-reference findings on submission. Eliminates the per-project audit cost on the scanner. Bigger build, not blocking.
- **Tier 3 — AI verifier prompt enrichment with version-specific compromise data.** Update `cloudflare/src/prompts/mini-shai-hulud.js` to list specific compromised versions per wave (May 11 TanStack hit versions X-Y, May 19 AntV hit versions A-B, etc.). Requires intel research. The AI verifier is currently OFF in prod anyway, so this is a future-work item.
- **Tier 4 — Dashboard "Triage Helper" UI.** A redesigned finding-detail panel that leads with the verdict chip + ActionRequired card, sorts findings by verdict (Confirmed first, Cleared at bottom or filtered out by default), and provides one-click "Acknowledge as false positive with these reasons" buttons that pre-fill the justification from `ScannerVerdictReason`. Belongs in the dashboard's own PR, not the scanner branch.
- **Worktree detection** — the wider discovery scope multiplies findings by N worktrees. A future enhancement detects `.git`-file (gitdir pointer) worktrees and either consolidates findings or tags them as "worktree of X." Real but not blocking.
- **Tighten the bundled IOC JSON's wildcards** — replace `@tanstack/*` etc. with pinned compromised versions from actual campaign disclosures. Operational, not code; can be done by updating the dashboard feed without touching the scanner.

---

## Real-box context (for the implementer in next session)

The PR-pending branch is `feature/wormcatcher-bounded-detection`, currently at `1841621`. **Do not open the PR yet** — the user wants this verdict/ActionRequired work landed on the same branch first, so the PR ships a coherent "authoritative, bounded, manager-actionable detection" story rather than just "we walk more drives now."

**Concrete validation expected before PR opens:**

1. After implementing this plan, re-run the same E2E that produced submission `32745acc-c644-4692-98ef-f3e53529df0b` (3 plants at `C:\WormcatcherE2ETest\` + full discovery + dev-dashboard submission). Compare the new submission's headline + finding list to the old one. Headline must say "COMPROMISED — 3 confirmed Tier-1, 62 cleared by npm audit" or similar, not "COMPROMISED — 65 Critical, 31 High."
2. Mac validation owed (still). Same script (`Verify-MshAcceptance.ps1` + this plan's new test cases) on a real Mac.
3. PR title remains: `feat: bounded, authoritative WormCatcher detection (checks 13/14 + discovery walk + npm-audit verdicts)`.
