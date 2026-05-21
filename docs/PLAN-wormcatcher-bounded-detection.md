# PLAN — WormCatcher bounded, authoritative detection

**Status:** ready to implement
**Branch:** `feature/mac-wormcatcher` (despite the name, this is cross-platform work — Windows + macOS)
**Owner:** next session
**Created:** 2026-05-21

---

## Tool goal (frozen — do not redesign this)

> RatCatcher / WormCatcher is a forensics tool that, when run on a workstation, gives a high-confidence belief that this machine **either does or does not carry the specific vulnerability being scanned for**.

For that statement to be defensible, **two properties must hold at the same time**:

1. **Authoritative coverage.** If the high-fidelity on-disk artifact of an active infection exists anywhere on this workstation, the scanner finds it. A "CLEAN" verdict must mean *we looked everywhere the artifact could plausibly be* and didn't find it.
2. **Bounded scan time.** The scanner must finish in a predictable wall-clock budget (target: **under 10 minutes** on a typical dev box) and must never recursively enumerate file trees where the artifact cannot live. A scan that hangs is worse than CLEAN — at least CLEAN gives ops something to act on.

These two properties are coupled: widening coverage without bounding it caused a 45-minute hang in an earlier attempt; narrowing coverage to stay fast caused today's false-clean reports when code lives outside `$env:USERPROFILE`. This plan satisfies both at once by separating **where we look for things** (discovery) from **what we check at each place** (surgical probes).

---

## Why today's scanner doesn't meet the goal

### Failure mode 1 — scanner can return CLEAN when machine is infected

- `$Path` in [Invoke-MiniShaiHulud.ps1:44](../Invoke-MiniShaiHulud.ps1) defaults to a hardcoded list under `$env:USERPROFILE` / `$HOME`. Code outside these folders (e.g. `C:\Atriora`, `D:\Repos`, project-specific layouts) is **invisible** to the scanner. Reported by user "Mark" — `C:\Atriora` example, screenshot in session transcript.
- The two **highest-fidelity on-disk artifacts** of a Shai-Hulud-class compromise are not checked at all:
  - **`bundle.js`** inside `node_modules/<compromised-pkg>/` — the worm payload itself
  - **`.github/workflows/shai-hulud-workflow.yml`** (and `shai-hulud.yml` / `shai-hulud.yaml` variants) — the worm's CI-persistence file, written into local repo clones after credential theft
- The 12 existing checks are mostly **behavioral / corroborating** (token atimes, shell history, cache modtimes). They support a finding but do not by themselves prove "this box ran the worm."

### Failure mode 2 — prior attempt to broaden coverage hung 45+ minutes

- Cause was a **recursive walk** that descended into `node_modules/` trees and never returned.
- Cause was **not** "looking at node_modules" — `node_modules/<bad-pkg>/bundle.js` is exactly where the smoking gun lives. The fix is *direct path probes* into known-bad subdirectories, **not** *recursive enumeration* of the whole tree.

---

## Design

### Phase 1 — Discovery (bounded)

**Goal:** produce a list of paths that could host the target artifacts, and stop. No file reads, no payload checks — just rooting.

**Marker-driven discovery.** Walk reachable filesystem looking for two markers:

- `.git` (file or directory) → indicates a git repo clone → eligible for the **workflow-file check**
- `package.json` → indicates a Node project root → eligible for the **payload-file check**

**Roots to start the walk from:**

| OS | Default starting roots |
|---|---|
| Windows | **All fixed drives AND all removable drives** (`Get-PSDrive -PSProvider FileSystem` where `DriveType -in 2,3` and ready). Rationale: a developer's USB / external SSD with project files would be a false-negative if excluded. Network drives (`DriveType 4`) are off by default — opt in via `-IncludeNetworkDrives`. Per-drive opt-out via `-ExcludeDrives D,E`. |
| macOS | `$HOME`, `/opt`, `/srv`, `/Volumes/*` (external mounts included; skip read-only volumes and Time Machine via volume info, not by name) |
| Linux | `$HOME`, `/opt`, `/srv`, `/media/*`, `/mnt/*` |
| Any | A user-supplied `-Path` argument **replaces** the defaults entirely. |

**Drive-level safety valves are mandatory** (they are what makes the all-drives default safe):

- Per-drive wall-clock cap **3 min** — if hit, log the drive as "partial scan" in the report header and move on
- Per-tree wall-clock cap **90 s** — if hit, prune that tree and continue
- Overall discovery cap **5 min** — if hit, log and proceed to Phase 2 with what we have
- Report header **must** name every drive that was partial-scanned or skipped, with reason

**Pruning rules (applied on directory entry, before descent):**

| Rule | Why |
|---|---|
| Depth limit ≤ 6 | Real projects sit near the root |
| Folder name matches deny list (see catalog) | Cache / build / system dirs don't host new project roots |
| Stop descending on entry into `node_modules`, `.pnpm`, `.yarn/cache`, `vendor`, `target`, `.git/objects`, `site-packages` | Vendored deps — anything inside is not a separate project |
| Skip reparse points (junctions, symlinks) | Source of infinite loops; also crosses VM / WSL / cloud boundaries |
| Skip cloud-sync placeholders | `FILE_ATTRIBUTE_OFFLINE` / `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` on Win; `.icloud` files / `~/Library/Mobile Documents` on Mac. Statting them triggers a cloud download. |
| Per-tree wall-clock cap 90s | Safety valve — log and prune the tree |
| Overall discovery cap 5 min | Safety valve — emit warning and proceed with what we have |

**Deny-list catalog (case-insensitive folder-name match):**

| Category | Folder names |
|---|---|
| Node | `node_modules`, `.pnpm`, `.yarn`, `bower_components` |
| Python | `site-packages`, `.venv`, `venv`, `env`, `__pycache__`, `.tox`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache` |
| .NET | `bin`, `obj`, `packages` *(see note below)* |
| Java/Kotlin | `target`, `build`, `.gradle` |
| Rust | `target` |
| Go | `pkg/mod`, `vendor` |
| Ruby/PHP | `vendor`, `.bundle` |
| iOS | `Pods`, `Carthage`, `DerivedData` |
| Web build | `.next`, `.nuxt`, `.svelte-kit`, `.parcel-cache`, `.turbo`, `.cache`, `dist`, `out` |
| VCS internals | `.git/objects`, `.svn`, `.hg` |
| Windows system | `Windows`, `Program Files`, `Program Files (x86)`, `ProgramData`, `$Recycle.Bin`, `System Volume Information`, `WinSxS`, `Installer`, `SoftwareDistribution` |
| Windows AppData traps | `AppData\Local\Microsoft`, `AppData\Local\Packages`, `AppData\Local\Temp`, `AppData\Roaming\npm-cache` |
| macOS system | `/System`, `/Library`, `/private`, `/Applications`, `~/Library/Caches`, `~/Library/Containers`, `~/Library/Group Containers`, `~/.Trash` |

> **Note on `bin` / `obj` / `packages`:** These are generic names that occasionally appear at project roots for non-.NET reasons. Apply the deny rule only when the folder also contains a hallmark .NET sibling (`.csproj` / `.sln` / `obj/project.assets.json`). When unsure, **allow descent** — false negatives in discovery are worse than slow scans.

**Output of Phase 1:** a list of `{ path, type }` objects where `type ∈ { git_repo, node_project, both }`. Recorded in the report header so a CLEAN result with 0 roots is visibly suspicious.

### Phase 2 — Surgical IOC probes (constant-time per probe, no walks)

**For each `git_repo` root:**

- **NEW Check 13 — worm workflow file (highest fidelity).** `Test-Path` for each filename in the IOC feed's `workflow_filenames` list under `<repo>/.github/workflows/`. Default list: `shai-hulud-workflow.yml`, `shai-hulud.yml`, `shai-hulud.yaml`. **Match = CRITICAL, confirmed compromise** — no legitimate code writes this file. Read the first 2 KB into the finding for the report.

**For each `node_project` root:**

- **NEW Check 14 — payload file present (highest fidelity).** For each IOC package matched in lockfile or `package.json`, `Test-Path` for `<root>/node_modules/<pkg>/bundle.js` (and any other filename in `payload_filenames` from the IOC feed). **Match = CRITICAL, confirmed execution.** Optionally hash the payload and compare against `payload_hashes` from the feed.
- **Existing checks 2 / 3 / 4** — keep: lockfile match, `package.json` match, `node_modules/<pkg>/` exists. Still valuable as "package is installed" evidence even when the payload has been cleaned.
- **Existing check 5** — keep: parse `package.json` `scripts` field, match against `suspicious_script_tokens`.
- **NEW corollary** — `.npmrc` at root: check for off-registry URLs and embedded credentials.

**For each workstation (run once, not per-root):**

- **NEW Check 15 — dropper artifact present.** `Test-Path` for each filename in the IOC feed's `dropper_filenames` list at each location in `dropper_drop_paths`. Default list: `processor.sh` at `/tmp/processor.sh`, `~/processor.sh`, and any `node_project` root discovered in Phase 1. **Match = CRITICAL, confirmed compromise** — these filenames are the worm's own staging artifacts and have no legitimate origin.
- **NEW Check 16 — TruffleHog drop in unexpected location.** `Test-Path` for a `trufflehog` / `trufflehog.exe` binary at each location in the IOC feed's `trufflehog_drop_paths` list (default: `/tmp/trufflehog`, `~/Downloads/trufflehog`, `~/.npm/_cacache/trufflehog`, npm cache root). If found, capture file size and mtime into the finding. **Match = HIGH** (a developer could legitimately install TruffleHog elsewhere, but not into these paths); promote to **CRITICAL** if mtime falls inside the IOC feed's `attack_window`.
- Existing checks 6–12 — keep as corroborating evidence, but **demote severity** when checks 13/14/15/16 don't fire. They're high-noise signals — useful alongside a confirmed artifact, but should not produce CRITICAL on their own.

### Severity model (updated — this is the headline behavior change)

| Trigger | Verdict |
|---|---|
| Check 13, 14, OR 15 fires | **CRITICAL — confirmed compromise** (Tier-1 IOCs: workflow file, payload, or dropper artifact) |
| Check 16 fires inside attack window | **CRITICAL — confirmed credential theft activity** |
| Check 16 fires outside attack window | **HIGH — TruffleHog in unexpected drop path; could be benign install but unusual** |
| Checks 2/3/4 fire (bad package installed) without 13/14/15 | **HIGH — installed but execution unproven; treat as compromised pending forensics** |
| Only checks 5–12 fire | **MEDIUM — suggestive, requires human review** |
| Nothing fires AND ≥ 1 scan root found | **CLEAN — high confidence** |
| Nothing fires AND 0 scan roots found | **INCONCLUSIVE — scanner saw no eligible roots; user must supply `-Path`** |

The **INCONCLUSIVE** state is the critical fix. Today the scanner returns CLEAN in the 0-roots case, which is the false-negative failure mode that breaks user trust.

### Report header changes

Every report (technical + executive briefing) must include, at the top, before any findings:

```
Scanner version: <ver>
IOC feed:        <source: network | bundled | cache | fallback-hardcoded>, updated <ts>
Scanned roots:   <N> total (<g> git repos, <n> Node projects)
Roots:           <bullet list of paths, capped at 50, with "+ N more" if elided>
Skipped paths:   <count, with reasons summarized: M deny-list, K reparse-points, L cloud-sync, P depth-cap>
Scan duration:   <secs>
```

This makes the "we looked everywhere we said we'd look" claim auditable by the manager triaging the report.

### IOC feed schema extension

Add optional fields to the IOC bundle at `https://mbfromit.com/ratcatcher/api/iocs/mini-shai-hulud`:

```json
{
  "payload_filenames":     ["bundle.js", "bundle.js.map"],
  "payload_hashes":        { "sha256": ["...", "..."] },
  "workflow_filenames":    ["shai-hulud-workflow.yml", "shai-hulud.yml", "shai-hulud.yaml"],
  "dropper_filenames":     ["processor.sh"],
  "dropper_drop_paths":    ["/tmp", "~", "<each node_project root>"],
  "trufflehog_drop_paths": ["/tmp/trufflehog", "~/Downloads/trufflehog", "~/.npm/_cacache/trufflehog"],
  "exfil_repo_names":      ["Shai-Hulud"],
  "exfil_repo_files":      ["data.json"]
}
```

> **`exfil_repo_names` / `exfil_repo_files`** describe the worm's GitHub-side persistence: after credential theft it creates a public repo on the victim's account named `Shai-Hulud` containing a `data.json` dump. This is a **remote** IOC — not checked by the workstation scanner (out of scope), but included in the feed so the dashboard / managers / a future GitHub-side scanner can use it. Document in the IOC catalog page on the dashboard.

Scanner must default these locally if the feed omits them (backward compat with older feeds and offline scans). Suggested defaults above.

---

## Files to change

All scanner-side changes land at the **repo root only**. The duplicate `RatCatcher/` + `cloudflare/RatCatcher/` trees were deleted in commit `03f2d22` (audited as outdated / no unique content) and gitignored.

1. `Invoke-MiniShaiHulud.ps1` (repo root)
2. `Private/MiniShaiHulud/Find-Msh*.ps1` helpers
3. `cloudflare/src/handlers/iocs.js` (Worker)
4. `cloudflare/src/iocs/mini-shai-hulud.js` (bundled fallback)

### New files

- `Private/MiniShaiHulud/Find-MshDiscoveryRoots.ps1` — Phase 1 walker, deny list, reparse-point + cloud-placeholder detection, per-drive / per-tree / overall caps
- `Private/MiniShaiHulud/Find-MshPayloadFile.ps1` — Check 14
- `Private/MiniShaiHulud/Find-MshWormWorkflow.ps1` — Check 13
- `Private/MiniShaiHulud/Find-MshDropperArtifact.ps1` — Check 15 (`processor.sh` and any other `dropper_filenames` at `dropper_drop_paths`)
- `Private/MiniShaiHulud/Find-MshTrufflehogDrop.ps1` — Check 16 (TruffleHog binary at any `trufflehog_drop_paths`)

### Modified files

- `Invoke-MiniShaiHulud.ps1` — replace hardcoded `$Path` default with a call to `Find-MshDiscoveryRoots`; invoke checks 13–16; emit new report header. Add `-ExcludeDrives`, `-IncludeNetworkDrives`, `-DiscoveryTimeoutSec` parameters.
- `Private/MiniShaiHulud/New-MshScanReport.ps1` — render new header (scanned roots, partial-scan drives, skipped paths)
- `Private/MiniShaiHulud/New-MshExecBriefing.ps1` — render new severity model
- `Private/MiniShaiHulud/Get-MshIocs.ps1` — accept new feed fields, default if absent
- `Private/MiniShaiHulud/MiniShaiHulud-IOCs.json` — add new fields to bundled fallback

### Cloudflare Worker side

- `cloudflare/src/handlers/iocs.js` — emit the new fields
- `cloudflare/src/iocs/mini-shai-hulud.js` — bundled IOC source updated with new fields + sensible defaults
- `cloudflare/src/prompts/mini-shai-hulud.js` — update if it references the feed schema

---

## Acceptance criteria

### Goal 1 — authoritative coverage

- [ ] **Payload positive test (Check 14):** Plant a fake `bundle.js` inside `<test-root>/node_modules/mbt/`. Scanner emits CRITICAL, regardless of whether `<test-root>` is under `$env:USERPROFILE`.
- [ ] **Workflow positive test (Check 13):** Plant `<test-root>/.github/workflows/shai-hulud-workflow.yml`. Scanner emits CRITICAL.
- [ ] **Dropper positive test (Check 15):** Plant `processor.sh` at `/tmp/processor.sh` (Mac/Linux) or `$env:TEMP\processor.sh` (Windows fallback location for the same probe). Scanner emits CRITICAL.
- [ ] **TruffleHog positive test (Check 16):** Plant a zero-byte `trufflehog` file at `/tmp/trufflehog` with an mtime inside `attack_window`. Scanner emits CRITICAL. With mtime well before the window, scanner emits HIGH.
- [ ] **Path coverage test:** With no `-Path` argument, a `bundle.js` planted under a **non-USERPROFILE** location (e.g. `C:\TestRepo\node_modules\mbt\bundle.js`) is still found because discovery walks fixed drives.
- [ ] **Zero-roots test:** Run on a machine with no git repos and no `package.json` anywhere discoverable. Scanner returns **INCONCLUSIVE**, not CLEAN.
- [ ] **Report header test:** Every report names the roots it scanned and the count of paths it skipped.

### Goal 2 — bounded scan time

- [ ] **Wall-clock test:** Synthetic dev box with 50 git repos, 200 `package.json` files, ~5 GB of `node_modules` — total scan completes in **< 10 minutes**.
- [ ] **No-hang test:** Planted symlink loop (`a → b → a`) on the discovery path does not extend scan time beyond the no-loop baseline by more than 10%.
- [ ] **Cloud-sync test:** A folder marked `FILE_ATTRIBUTE_OFFLINE` (OneDrive on-demand) is skipped without triggering a download. Verify by monitoring network bytes.
- [ ] **Deny-list test:** `node_modules` is *entered* (so checks 4 / 14 can probe direct paths) but never *recursively enumerated*. Verify by instrumenting the walker with a counter.

### Regression — existing behavior

- [ ] All 12 existing checks still fire on their existing test fixtures.
- [ ] Existing Pester suite passes on both Windows and macOS (the latter being the original purpose of this branch — see `project_handoff_2026_05_21_mac_branch_paused.md`).

---

## Open questions — RESOLVED 2026-05-21 turn-2

1. **The duplicate trees.** ✅ Audited (`RatCatcher/` was an older clone, `cloudflare/RatCatcher/` was a stale copy — both had no unique content). **Deleted and gitignored in commit `03f2d22`.** Implementation lands in one tree only.
2. **Branch name.** ✅ Keep `feature/mac-wormcatcher` (don't rename). PR title: `feat: bounded, authoritative WormCatcher detection (checks 13/14 + discovery walk)`.
3. **Default Windows discovery scope.** ✅ **All fixed drives + all removable drives**, network off by default. User raised the USB-dev-drive false-negative case; removable inclusion fixes it. Per-drive 3-min, per-tree 90-s, overall 5-min wall-clock caps keep this bounded. `-ExcludeDrives` / `-IncludeNetworkDrives` to tune.

---

## Suggested commit sequence

1. Add `Find-MshDiscoveryRoots.ps1` + tests (no behavior change to existing checks yet).
2. Add `Find-MshPayloadFile.ps1` + `Find-MshWormWorkflow.ps1` + `Find-MshDropperArtifact.ps1` + `Find-MshTrufflehogDrop.ps1` + tests, wired into the existing scan flow.
3. Wire Phase 1 discovery into `Invoke-MiniShaiHulud.ps1` as the new `$Path` source; preserve the old USERPROFILE defaults as a fallback layer only if discovery yields zero roots (transition safety).
4. Update report templates (`New-MshScanReport.ps1`, `New-MshExecBriefing.ps1`) with the new header + severity model (Tier-1 IOC list: checks 13, 14, 15, plus 16 inside attack window).
5. Extend IOC feed schema + bundled JSON with `dropper_filenames`, `dropper_drop_paths`, `exfil_repo_names`, `exfil_repo_files`; ensure scanner handles missing fields gracefully.
6. Update Worker handler + prompts to emit new fields. Deploy worker **after** the scanner is verified to handle absent fields.
7. Update macOS + Windows quick-starts in `README.md` to reflect the new behavior.

---

## Rollback

This branch has no PR open. If the implementation goes sideways:

- `git reset --hard origin/main` on the branch is safe — nothing downstream depends on it.
- The IOC feed schema extension is **backward compatible** by design (new fields are optional with sensible defaults), so a partial deploy is recoverable: roll the scanner forward first, then the worker, never the reverse.
