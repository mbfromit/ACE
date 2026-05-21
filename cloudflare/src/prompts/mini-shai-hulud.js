export const systemPrompt = `You are a cybersecurity analyst verifying forensic scanner findings against a known attack profile. You will receive:
1. A reference brief describing the Mini Shai-Hulud npm supply chain worm (TeamPCP, April–May 2026)
2. A specific finding from a forensic scanner that ran on an engineer workstation

Your job is to determine whether the finding is genuinely related to this specific campaign or is likely a false positive (normal system activity unrelated to it).

RESPOND WITH EXACTLY ONE LINE in this format:
VERDICT: <Confirmed|Likely|Unlikely|FalsePositive> | REASON: <one sentence explanation>

Definitions:
- Confirmed: Finding directly matches a known IOC (exact compromised package@version, exact exfil URL/host, GitHub Actions runner artifact present, suspicious postinstall executing decoded base64 with child_process)
- Likely: Finding is consistent with the campaign's TTPs but not an exact IOC match (e.g., Bun binary recently installed in attack window, npm publish events from a developer who does not normally publish, token files accessed during attack window)
- Unlikely: Finding has weak or coincidental connection (e.g., Bun present but not modified recently, ~/.npmrc atime change with no other corroborating evidence)
- FalsePositive: Finding is clearly unrelated normal activity (e.g., a developer who legitimately uses Bun, scheduled CI runner on a known build host, package install of a clean version of an affected scope)

Be strict. Mini Shai-Hulud is polymorphic and moves fast — the IOC list is not exhaustive. Lean toward Likely (not Confirmed) unless an exact package@version, exfil endpoint, or runner artifact is present. Lean toward FalsePositive for ambient developer activity that lacks campaign-specific markers.
Do not think out loud. Do not include any text before or after the verdict line.`

export const articleContext = `REFERENCE: Mini Shai-Hulud npm Supply Chain Worm — April–May 2026 (TeamPCP)

OVERVIEW:
Mini Shai-Hulud is a self-propagating npm supply chain worm that first appeared in late April 2026 and is attributed by StepSecurity and others to a threat group tracked as TeamPCP. It is a variant of the original 2025 Shai-Hulud worm but with a smaller per-package payload and a heavier reliance on CI/CD trust abuse. By mid-May 2026 the campaign had compromised 170+ npm packages across 400+ malicious versions, including bursts of 300+ versions in 22-minute automated publishing windows.

KEY DISTINGUISHING TRAIT:
This is not primarily a workstation RAT. The campaign lives in CI runners, stolen npm tokens, and abused GitHub Actions trust chains. Workstation forensics catch the tail of the compromise; the head sits in registry-side artifacts and identity-plane logs that a workstation scanner cannot see.

ATTACK MECHANISM:
1. Initial foothold via a compromised maintainer (phishing, leaked token, or pulled forward from a prior victim).
2. npm postinstall lifecycle script executes on developer/CI machines. The worm often uses the **Bun** JavaScript runtime to dodge Node-targeted EDR rules.
3. Token harvesting: walks env vars, ~/.npmrc, ~/.docker/config.json, GitHub Actions $ACTIONS_RUNTIME_TOKEN, AWS/GCP credential files, SSH keys.
4. OIDC / SLSA abuse: chains a GitHub Actions "Pwn Request" + cache poisoning + a legitimately-issued OIDC token to publish trojanized packages with VALID SLSA provenance. The TanStack wave (May 11, 2026) was the first publicly documented case of a malicious npm package carrying valid SLSA provenance.
5. Self-propagation: with stolen npm tokens, the worm publishes trojanized versions of every other package the victim maintains. The AntV wave (May 19, 2026) published 300+ versions across 323 packages in 22 minutes.
6. Exfiltration: harvested secrets and payload bundles are pushed to attacker-controlled GitHub repositories and webhooks. Endpoints rotate per wave.

KNOWN COMPROMISED PACKAGES (non-exhaustive, list keeps growing):
- @cap-js/sqlite@2.2.2
- @cap-js/postgres@2.2.2
- @cap-js/db-service@2.10.1
- mbt@1.2.48
- @tanstack/* (multiple versions, May 11 wave)
- @antv/* (multiple versions, May 19 wave)
- @uipath/* (multiple versions)
- @squawk/* (multiple versions)
- @tallyui/* (multiple versions)
- @mistralai/* (multiple versions)
- Two PyPI packages have also been identified.

ATTACK WINDOW:
- Start: 2026-04-01 00:00 UTC (first known wave hitting @cap-js and mbt)
- End: ongoing as of 2026-05-21

TTP MARKERS (what to look for on a workstation):
- Lockfile or package.json references to any known compromised name@version.
- Physical presence of a known-bad package version in node_modules (lockfile may have been cleaned up — read the installed version directly).
- postinstall or preinstall scripts in installed packages containing: eval(...), Function(...), Buffer.from(... ,'base64'), atob(...), child_process invocations, the literal token "bun ", curl/wget shell-outs, fetches to non-registry hostnames, base64 blobs longer than ~200 characters.
- The Bun runtime present on PATH. By itself this is benign — many teams legitimately use Bun. Suspicious only when the bun binary LastWriteTime falls inside the attack window OR ~/.bun/install/cache has activity inside the attack window.
- Token files (~/.npmrc, ~/.docker/config.json, ~/.config/gh/hosts.yml, ~/.aws/credentials, ~/.aws/config, ~/.ssh/id_* private keys, ~/.gitconfig, ~/.netrc) showing access timestamps inside the attack window. Note: atime is unreliable on Windows (disabled by default) and on noatime/relatime Unix mounts — treat as corroborating evidence, not standalone proof.
- GitHub Actions self-hosted runner artifacts on a developer workstation: _work/, .runner, _diag/ directories under HOME, C:\\actions-runner\\, /opt/actions-runner/. A dev box that doubles as a self-hosted runner is the actual blast radius for token theft.
- Recent activity inside the attack window under ~/.npm/_logs/, ~/.npm/_cacache/, ~/.yarn/cache/, ~/.local/share/pnpm/store/, node_modules/.cache/ — especially when filenames cross-reference the compromised package list.
- DNS cache or active TCP connections to known exfil endpoints, attacker-controlled GitHub raw URLs, or webhooks listed in the current IOC feed.
- "npm publish" events in bash/zsh/PowerShell history for users who do not normally publish, or from machines that should not publish, especially inside the attack window.

WHAT IS NOT A WORKSTATION SIGNAL (out of scope for this scanner):
- CI runner state on dedicated build infrastructure.
- npm registry-side audit (publisher accounts, token issuance logs).
- GitHub Actions workflow run logs.
- OIDC token replay against AWS/GCP — those leave traces only in cloud control planes.
- SLSA provenance verification — the worm has demonstrated that valid provenance is no longer a safety guarantee for this campaign.

ATTRIBUTION:
StepSecurity attributes the campaign to TeamPCP, the same group responsible for the March 2026 compromise of Aqua Security's Trivy scanner and the April 2026 Bitwarden CLI npm package compromise. Microsoft Security Research has separately tracked the resurgence as "Shai-Hulud 2.0".

REMEDIATION GUIDANCE (for the runbook to surface alongside any Confirmed/Likely finding):
- Immediately revoke any npm tokens the affected user holds: 'npm token list' / 'npm token revoke <id>'.
- Rotate cloud credentials touched during the attack window (AWS access keys, GCP service account keys, Azure SPN secrets).
- Rotate SSH private keys present on the machine.
- Audit .github/workflows/*.yml in every repository the user touches for 'pull_request_target' chained with checkout of the PR head ref — the canonical Pwn Request pattern.
- Enforce 'npm ci' (not 'npm install') in CI/CD; require provenance verification on the internal registry.
- Block egress to known exfil hosts at the network edge once they are identified in the feed.
- Treat any machine that has hosted a self-hosted GitHub Actions runner as fully compromised if a finding is Confirmed or Likely.`

export const userPromptIntro = 'Evaluate this finding. Is it related to the Mini Shai-Hulud npm supply chain worm described above, or is it a false positive?'
