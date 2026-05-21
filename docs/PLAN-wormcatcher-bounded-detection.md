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
| Windows | All fixed drives (`Get-PSDrive -PSProvider FileSystem` where ready and `DriveType -eq 3`). Excludes network and removable by default — `-IncludeRemote` / `-IncludeRemovable` to opt in. |
| macOS | `$HOME`, `/opt`, `/srv`, `/Volumes/*` (skip read-only volumes and Time Machine) |
| Linux | `$HOME`, `/opt`, `/srv` |
| Any | A user-supplied `-Path` argument **replaces** the defaults entirely. |

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

- Existing checks 6–12 — keep as corroborating evidence, but **demote severity** when checks 13/14 don't fire. They're high-noise signals — useful alongside a confirmed artifact, but should not produce CRITICAL on their own.

### Severity model (updated — this is the headline behavior change)

| Trigger | Verdict |
|---|---|
| Check 13 OR 14 fires | **CRITICAL — confirmed compromise** |
| Checks 2/3/4 fire (bad package installed) without 13/14 | **HIGH — installed but execution unproven; treat as compromised pending forensics** |
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
  "trufflehog_drop_paths": ["/tmp/trufflehog", "~/Downloads/trufflehog"]
}
```

Scanner must default these locally if the feed omits them (backward compat with older feeds and offline scans). Suggested defaults above.

---

## Files to change

All scanner-side changes land in three locations until the duplicate-tree question (see Open Questions) is resolved:

1. `Invoke-MiniShaiHulud.ps1` (repo root)
2. `RatCatcher/Invoke-MiniShaiHulud.ps1` *(currently untracked — see Open Q1)*
3. `cloudflare/RatCatcher/Invoke-MiniShaiHulud.ps1` *(currently untracked — see Open Q1)*

Plus the matching `Private/MiniShaiHulud/Find-Msh*.ps1` helpers in each tree.

### New files (per tree)

- `Private/MiniShaiHulud/Find-MshDiscoveryRoots.ps1` — Phase 1 walker, deny list, reparse-point + cloud-placeholder detection
- `Private/MiniShaiHulud/Find-MshPayloadFile.ps1` — Check 14
- `Private/MiniShaiHulud/Find-MshWormWorkflow.ps1` — Check 13

### Modified files (per tree)

- `Invoke-MiniShaiHulud.ps1` — replace hardcoded `$Path` default with a call to `Find-MshDiscoveryRoots`; invoke checks 13/14; emit new report header
- `Private/MiniShaiHulud/New-MshScanReport.ps1` — render new header
- `Private/MiniShaiHulud/New-MshExecBriefing.ps1` — render new severity model
- `Private/MiniShaiHulud/Get-MshIocs.ps1` — accept new feed fields, default if absent
- `Private/MiniShaiHulud/MiniShaiHulud-IOCs.json` — add new fields to bundled fallback

### Cloudflare Worker side

- `cloudflare/src/handlers/iocs.js` (and the duplicate at `cloudflare/RatCatcher/cloudflare/src/handlers/iocs.js`) — emit the new fields
- `cloudflare/src/prompts/mini-shai-hulud.js` — update if it references the feed schema

---

## Acceptance criteria

### Goal 1 — authoritative coverage

- [ ] **Payload positive test:** Plant a fake `bundle.js` inside `<test-root>/node_modules/mbt/`. Scanner emits CRITICAL via Check 14, regardless of whether `<test-root>` is under `$env:USERPROFILE`.
- [ ] **Workflow positive test:** Plant `<test-root>/.github/workflows/shai-hulud-workflow.yml`. Scanner emits CRITICAL via Check 13.
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

## Open questions — resolve before writing code

1. **The duplicate trees.** `RatCatcher/` and `cloudflare/RatCatcher/` are currently untracked in the working tree. They were `A` (staged adds) at the start of one prior session but ended up untracked. Were they supposed to be committed? Are they deploy artifacts that should be `.gitignore`d? **Decide before touching code** — the answer determines whether changes land in one place or three.
2. **Branch name.** `feature/mac-wormcatcher` is now a misnomer; this is cross-platform work. User said "let's just do it on this branch" so don't rename, but the PR title should describe the actual change, e.g. `feat: bounded, authoritative WormCatcher detection (checks 13/14 + discovery)`.
3. **Default Windows discovery scope.** Walking *all* fixed drives is correct for authoritative coverage but slow if the box has a 4 TB media drive. **Recommend:** default to `C:\` only; require `-IncludeAllDrives` to widen; emit a warning in the report header when other fixed drives exist but weren't scanned.

---

## Suggested commit sequence

1. Add `Find-MshDiscoveryRoots.ps1` + tests (no behavior change to existing checks yet).
2. Add `Find-MshPayloadFile.ps1` + `Find-MshWormWorkflow.ps1` + tests, wired into the existing scan flow.
3. Wire Phase 1 discovery into `Invoke-MiniShaiHulud.ps1` as the new `$Path` source; preserve the old USERPROFILE defaults as a fallback layer only if discovery yields zero roots (transition safety).
4. Update report templates (`New-MshScanReport.ps1`, `New-MshExecBriefing.ps1`) with the new header + severity model.
5. Extend IOC feed schema + bundled JSON; ensure scanner handles missing fields gracefully.
6. Update Worker handler + prompts to emit new fields. Deploy worker **after** the scanner is verified to handle absent fields.
7. Update macOS + Windows quick-starts in `README.md` to reflect the new behavior.

---

## Rollback

This branch has no PR open. If the implementation goes sideways:

- `git reset --hard origin/main` on the branch is safe — nothing downstream depends on it.
- The IOC feed schema extension is **backward compatible** by design (new fields are optional with sensible defaults), so a partial deploy is recoverable: roll the scanner forward first, then the worker, never the reverse.
