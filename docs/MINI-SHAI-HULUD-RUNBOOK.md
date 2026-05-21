# Mini Shai-Hulud Scanner — Engineer Runbook

## What this is

`Invoke-MiniShaiHulud.ps1` is a workstation forensic scanner for the **Mini Shai-Hulud** npm supply-chain worm (TeamPCP, April–May 2026 onward). It is a separate script from `Invoke-RatCatcher.ps1` (which scans for the March 31, 2026 Axios campaign). Both submit to the same RatCatcher dashboard; the dashboard distinguishes them with a campaign tag.

## What this is NOT

**This scanner does not certify that your machine is clean.** It reports findings produced by twelve checks at the moment it ran. Mini Shai-Hulud is polymorphic, fast-moving, and primarily lives in CI runners and stolen npm tokens — not on workstations. A workstation scan catches the tail of the compromise, not the head. Pair this scanner with token rotation and CI audit (below).

## Prerequisites

- PowerShell 7.0+ (same as the Axios scanner)
- Network access to `https://mbfromit.com/ratcatcher/` for the live IOC feed and submission. If air-gapped, the scanner uses a bundled IOC JSON instead.

## Download

```powershell
git clone https://github.com/mbfromit/RatCatcher.git
cd RatCatcher
```

Engineers who already cloned the repo for the Axios scanner: `git pull` is enough.

## Run

```powershell
# Default: scan common dev folders, prompt for submission password
./Invoke-MiniShaiHulud.ps1

# Scan a specific folder
./Invoke-MiniShaiHulud.ps1 -Path C:\Dev

# No upload (offline / air-gapped)
./Invoke-MiniShaiHulud.ps1 -NoSubmit

# Pinned IOC bundle from disk (skip network)
./Invoke-MiniShaiHulud.ps1 -NoIocNetwork

# Pass password non-interactively (CI use)
./Invoke-MiniShaiHulud.ps1 -SubmitPassword 'xxx' -NonInteractive
```

Reports land in `C:\Logs` (Windows) or `/tmp` (macOS/Linux) by default. Override with `-OutputPath`.

## Verdict labels and exit codes

The scanner reports one of three local verdicts based on the highest-severity finding:

| Local verdict | Meaning | Exit code |
|---|---|---|
| `CLEAN` | No findings produced by any of the 12 checks | 0 |
| `REVIEW` | High-severity findings present but **no Critical IOC match**. Almost always token-file access timestamps (check 8) or recent npm cache activity (check 10) — corroborating evidence only. Open the report, glance, ignore unless paired with Critical later. | 0 |
| `COMPROMISED` | One or more Critical findings — a known IOC matched something on this machine. Treat as an incident and follow the mitigation steps below. | 1 |

The exit code is engineered so `REVIEW` does **not** break CI gates. Only `COMPROMISED` (Critical IOC match) returns non-zero.

The dashboard receives `COMPROMISED` for both `REVIEW` and `COMPROMISED` local verdicts (so manager review + AI verification still engage). The distinction is purely local so engineers do not see a false `COMPROMISED` label on every scan.

## What the 12 checks look for

| # | Check | What it scans | Severity |
|---|---|---|---|
| 1 | Project discovery | `package.json` files under the scan path | n/a |
| 2 | Lockfile match | npm / yarn / pnpm lockfiles for IOC `name@version` (scope wildcards supported) | Critical |
| 3 | Manifest match | `package.json` dependencies directly referencing IOC packages | Critical |
| 4 | Installed match | `node_modules/<scope>/<name>/package.json` — catches anti-forensic lockfile cleanup | Critical |
| 5 | Suspicious install scripts | `postinstall`/`preinstall` containing `eval(`, `Function(`, `Buffer.from(`, `atob(`, `bun `, `child_process`, long base64 blobs | High; Critical when decode + exec combined |
| 6 | Bun runtime | Bun on PATH + attack-window LastWriteTime or `~/.bun/install/cache` activity | Informational by default; High with corroborating activity |
| 7 | npm cache | `~/.npm/_cacache` and `npm root -g` for IOC packages | High (cache) / Critical (global install) |
| 8 | Token-file atime | `~/.npmrc`, `~/.docker/config.json`, `~/.config/gh/hosts.yml`, `~/.aws/credentials`, `~/.aws/config`, `~/.ssh/id_*` (private keys), `~/.gitconfig`, `~/.netrc` accessed inside attack window | High — see atime caveat below |
| 9 | GHA runner artifacts | `actions-runner/`, `_work/`, `.runner` under HOME, `C:\actions-runner\`, `/opt/actions-runner/` | Critical |
| 10 | Recent cache activity | Files modified inside attack window under `~/.npm/_logs/`, `~/.yarn/cache/`, `~/.local/share/pnpm/store/` | High (Critical if filename matches IOC list) |
| 11 | Network evidence | DNS cache + active TCP connections vs IOC exfil hosts | Informational (no hosts in feed yet) / High (DNS hit) / Critical (active connection) |
| 12 | Shell history | `npm publish` in bash/zsh/PSReadline history (zsh extended history filtered to attack window) | High |

### Atime caveat (check 8)

Last-access-time is unreliable on:

- Windows volumes — disabled by default since the NTFS atime perf tweak
- Unix mounts mounted with `noatime` or `relatime`

Treat any TokenTouch finding as **corroborating** evidence, not standalone proof. If a Token Touch fires alone with no BadPackage or RunnerArtifact, lean toward False Positive. If it fires alongside any Critical finding, treat it seriously.

## What this scanner does NOT cover (out of scope)

- CI runner state on dedicated build infrastructure
- npm registry-side audit (publisher accounts, token issuance logs)
- GitHub Actions workflow run logs
- OIDC token replay against AWS/GCP — those leave logs only in cloud control planes
- SLSA provenance verification — the worm has demonstrated valid provenance is no longer a safety guarantee
- New IOC packages not yet in the feed (the IOC list updates frequently — re-run after each wave is disclosed)
- Compromise that has cleaned up after itself with no residual disk evidence
- Packages installed via `bun install` into Bun's own store rather than `node_modules`

## If a finding is Confirmed or Likely (per AI verdict)

Do this immediately, in order:

1. **Disconnect the machine from the network** if check 11 shows an active connection.
2. **Revoke npm tokens this user holds:**
   ```
   npm token list
   npm token revoke <token-id>
   ```
3. **Rotate cloud credentials** touched during the attack window (AWS access keys via `aws iam create-access-key` then delete the old one; GCP service-account keys; Azure SPN secrets).
4. **Rotate SSH private keys** present on the machine — regenerate and update authorized_keys everywhere they were used.
5. **Audit GitHub Actions workflows** in every repository this user can write to. Look in `.github/workflows/*.yml` for the canonical **Pwn Request** pattern:
   - `on: pull_request_target` triggers
   - `actions/checkout` with `ref: ${{ github.event.pull_request.head.ref }}` or `${{ github.event.pull_request.head.sha }}`
   - Followed by code execution (npm install, build steps, anything that runs untrusted PR code with secrets in env)
6. **Replace `npm install` with `npm ci` in CI workflows** so package-lock.json drift cannot pull poisoned versions.
7. **If check 9 fired (runner artifacts present),** treat the machine as runner infrastructure. The blast radius is everything the runner ever held tokens for. Coordinate with whoever owns the runner's labels/queues.
8. **Escalate to ops.** Mini Shai-Hulud has organization-wide blast radius via shared tokens; one-machine remediation is not enough.

## After remediation

Re-run the scanner with the same arguments. A clean result *with the same IOC feed version* is meaningful. A clean result against a newer feed version may indicate either successful remediation or expanded detection.

## Updating the IOC feed (ops)

The IOC bundle is served from `cloudflare/src/iocs/mini-shai-hulud.js` as a worker constant. To update during a wave:

1. Edit the constant (new packages, new exfil hosts, etc.).
2. Bump `updated_at`.
3. `cd cloudflare && npx wrangler deploy --env dev` then promote to prod.

If updates start exceeding one deploy per week, migrate the bundle to Cloudflare KV — tracked as a follow-up in the design plan.

## Reference reading

- Picus — [Mini Shai-Hulud: The npm Supply Chain Worm Explained](https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained)
- Snyk — [AntV wave](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/) and [TanStack wave](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- Akamai — [Mini Shai-Hulud: The Worm Returns and Goes Public](https://www.akamai.com/blog/security-research/mini-shai-hulud-worm-returns-goes-public)
- Wiz — [TanStack + more npm Packages Compromised](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- Microsoft — [Shai-Hulud 2.0 detection and response guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
