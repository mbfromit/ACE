# Bedrock Safety Checklist — Axxess Compliance Engine (ACE)

**Audience:** Security / legal / engineering management reviewing whether the ACE scanner suite is safe to point at Anthropic Claude Opus 4.7 on AWS Bedrock.

**Status of this document:** Engineering controls described under §3 are landed and verified on branch `feature/wormcatcher-bounded-detection` (PR #2). The Bedrock onboarding itself (account, region, IAM, allowlist entry) has not happened — this document defines what needs to be in place before it does.

---

## 1. What ACE is and what it sends to an LLM

ACE is two scanners that run on developer workstations and submit findings to a shared dashboard:

- **Axios scanner (`Invoke-ACE.ps1`)** — looks for the March 2026 Axios supply-chain compromise.
- **WormCatcher (Mini Shai-Hulud scanner)** — looks for the April–May 2026 npm worm.

Both scanners produce HTML reports and submit them to a Cloudflare Worker, which stores the reports in R2 and writes summary rows to D1. An AI verifier component (currently OFF in production — see §4) consumes finding content from the report HTML and produces per-finding verdicts (Confirmed / Likely / Unlikely / FalsePositive). The verifier currently calls a self-hosted Ollama (Gemma) tunnel; the Bedrock migration would replace that destination with Anthropic Claude Opus 4.7.

The LLM input for one verification call is a structured prompt containing:

1. A reference article describing the campaign (publicly published threat-intel writeup).
2. The scanner finding — `category`, `description`, and a short `detail` excerpt.

**The finding content is the only field that varies per call and is the only field that can carry user-originated content from the scanned workstation.**

## 2. Posture we are relying on Bedrock to provide

Bedrock's contractual posture (current as of plan authoring; reverify before sign-off):

- **No model-provider visibility into prompts or completions.** Anthropic does not see Bedrock-routed traffic.
- **No training on customer data.** Prompts and completions are not used to train or fine-tune models.
- **Region pinning.** Traffic is processed in the AWS region the inference is invoked from.
- **Invocation logging is off by default.** When enabled (operator opt-in), logs land in customer-controlled CloudWatch / S3 with customer KMS.

If any of these change, the data-handling argument in this document changes with them.

## 3. Engineering prerequisites (LANDED on PR #2)

### 3a. Scanner-side secret redaction at the choke point

**Risk closed:** scanner captures free-form content (shell-history lines, package.json install hooks, workflow YAML excerpts) that on a real workstation can carry inline credentials — NPM_TOKEN, GitHub PATs, AWS keys, Bearer tokens, basic-auth URLs.

**Control:** `Private/Shared/Redact-Secrets.ps1` defines a pattern set covering:

| Kind | Pattern shape |
|---|---|
| npm publish tokens | `npm_` + 36+ char body |
| GitHub PAT (classic) | `ghp_` |
| GitHub OAuth | `gho_` |
| GitHub fine-grained PAT | `github_pat_` + 82-char body |
| AWS access key IDs | `AKIA` / `ASIA` + 16 alphanumeric |
| AWS secret keys | `aws_secret_access_key = …` contextual |
| CLI credential flags | `--token`, `--otp`, `_authToken`, `NPM_TOKEN=…`, `GITHUB_TOKEN=…` |
| Bearer header | `Bearer ` + 20+ char token body |
| basic-auth URL | `https?://user:pass@` (host preserved, userinfo stripped) |

Each match is replaced with a `<REDACTED:kind>` marker. The redactor is invoked from `Private/Shared/New-Finding.ps1` — the choke point every WormCatcher finding flows through — on `$Description` (always) and on a whitelist of free-form `$Extra` keys (`Command`, `Script`, `Excerpt`, `FileExcerpt`, `Content`, `Line`, `Snippet`). When any pattern fires, `Extra.RedactionApplied = true` is set on the finding so the rendered report flags that scrubbing happened.

**Verification evidence:**
- `Tests/Shared/Redact-Secrets.Tests.ps1` — 21 unit tests covering each pattern, idempotency, no-false-positive prose, basic-auth scheme/host preservation, multi-secret single line.
- `Tests/MiniShaiHulud/Find-MshShellHistoryPublishes.Tests.ps1` — 5 integration tests; synthetic `.bash_history` lines containing NPM_TOKEN, --token, GITHUB_TOKEN, basic-auth URL fed through the production finder; assertions that no raw secret substring survives in the emitted finding.
- `Tests/MiniShaiHulud/Find-MshSuspiciousScripts.Tests.ps1` (extended) — 2 new integration tests; synthetic `package.json` postinstall/preinstall hooks containing ghp_ tokens and NPM_TOKEN env assignments combined with IOC trigger tokens (`child_process`, `eval(`); assertions that IOC detection still fires AND the credential is redacted.

### 3b. Worker-side AI endpoint allowlist

**Risk closed:** `env.AI_TUNNEL_URL` is a Cloudflare Worker secret. Before this control, one `wrangler secret put` could repoint the AI verifier from the self-hosted Ollama tunnel to any third-party LLM endpoint with no code review. That swap is the exact moment the data-handling story changes — Bedrock's posture only protects traffic to Bedrock.

**Control:** `cloudflare/src/config/ai-endpoints.js` exports `APPROVED_AI_ENDPOINTS`, an array of permitted base URL prefixes, and `assertApprovedEndpoint(env)`, which throws on missing or non-allowlisted `AI_TUNNEL_URL`. The gate is invoked at four sites in `cloudflare/src/handlers/ai-verify.js`:

- Top of `verifySubmissionFindings` (orchestrator — fast-fails before any DB write so a misconfigured URL doesn't leave submissions in transient `AI_PENDING` state).
- Top of `checkModelStatus`, `warmUpModel`, `verifyOneFinding` — defense in depth at every fetch site.

**Initial allowlist is empty.** Re-enabling the AI verifier requires both (a) adding the destination URL prefix to `ai-endpoints.js` (a code change subject to PR review) AND (b) setting the Cloudflare secret. Either alone is insufficient. **The control is the file in git, not the secret.**

**Verification evidence:**
- `cloudflare/test/ai-endpoint-gate.test.js` — 11 vitest cases covering: undefined / empty / null env, non-allowlisted URL, empty allowlist (fail-closed), prefix match admits, prefix-only-match footgun (same-prefix attacker domain admitted unless allowlist entry ends in `/`), integration with `verifySubmissionFindings` proving no fetch issued and no DB write happens when the gate rejects.

## 4. Residual risks honestly stated

These risks **are not closed by this branch** and must be considered before approving Bedrock onboarding:

### 4a. WormCatcher-only scope

The redaction work at §3a covers **only the WormCatcher (Mini Shai-Hulud) scanner**. The Axios scanner (`Invoke-ACE.ps1`) emits findings via a separate path that does NOT flow through `Private/Shared/New-Finding.ps1` and therefore is NOT subject to the redactor. The Bedrock data-handling claim *"no plaintext credentials in the payload"* holds **for WormCatcher submissions only**.

**Mitigation options:**
- Narrow the Bedrock claim to `campaign = 'mini-shai-hulud'` submissions only, and route Axios submissions to a separate (non-Bedrock) verifier or no verifier.
- Or, as a follow-up PR, extend the redactor to wrap the Axios finding factory too.

### 4b. D1 stores AI input text

`cloudflare/src/handlers/ai-verify.js` line ~239 writes `finding.detail.slice(0, 500)` into the `finding_ai_verdicts.description` column. That excerpt is the first 500 characters of the redacted finding content. With §3a in place, those 500 characters never contain plaintext credentials matching the §3a patterns — but the D1 storage is a real secondary surface that should be acknowledged in any data-retention policy. D1 rows are subject to the same backup / replication posture as the rest of the schema.

### 4c. Patterns not covered by §3a redactor

The §3a pattern set is opinionated to high-confidence shapes. It does **not** cover:

- Generic OAuth tokens with no distinguishing prefix (e.g. raw 40-char hex blobs without a Bearer header).
- Customer-specific API key formats (e.g. `sk-…` from non-OpenAI services that happen to mint similar keys).
- High-entropy strings that are credentials but lack a recognizable prefix.

This is an intentional tradeoff to keep the false-positive rate near zero on plain English prose. Operators submitting from workstations with non-standard credential formats should plan a redactor extension or accept the residual.

### 4d. Shared submit password is one credential for all operators

`SubmitPassword` is a single shared secret used by every workstation to authenticate to the dashboard. Compromise of that password compromises the integrity of every submission, not just one. Out of scope for Bedrock specifically but worth flagging — Bedrock cares about prompt content; the dashboard cares about submission attribution.

### 4e. Aggregated metadata is still identifying

The dashboard schema records `hostname`, `username`, `scan_timestamp`, `paths_scanned`. None of those are credentials, but they identify the workstation and operator. Bedrock will not see metadata (the AI verifier only sees finding content), but the metadata is in D1.

## 5. AWS account / region / IAM recommendations

Before turning on the Bedrock destination:

### 5a. Account isolation

- Dedicate an AWS account to ACE's Bedrock usage. Do not co-mingle with production application traffic. Reduces blast radius if the Worker is compromised.

### 5b. Region pinning

- Choose one Bedrock-supported region (e.g. `us-east-1`) and lock the Worker to that region only. The allowlist entry should be the regional Bedrock endpoint, not a generic `bedrock.amazonaws.com` (which would admit any region).
- Example allowlist entry: `https://bedrock-runtime.us-east-1.amazonaws.com/`.

### 5c. IAM least-privilege

- Create a single IAM role for the Worker's Bedrock access.
- Grant only `bedrock:InvokeModel` (and `bedrock:InvokeModelWithResponseStream` if streaming is used).
- Scope the resource to the specific Claude Opus 4.7 model ARN, not `*`.
- Deny all other Bedrock actions explicitly (`bedrock:CreateModelCustomizationJob`, `bedrock:PutFoundationModelEntitlement`, etc.) so an exfiltration path via training-job submission is closed.

### 5d. KMS

- Enable customer-managed KMS keys for any Bedrock invocation logging (if operator-enabled per §2).
- The same KMS key controls who can read the logs.

### 5e. Logging posture

- Default: invocation logging OFF. Bedrock prompts contain finding content that, while redacted per §3a, is still operationally sensitive.
- If logging is enabled for debugging, scope retention tightly (e.g. 7 days) and restrict log group read access to a named on-call group.

### 5f. Network egress

- The Worker reaches Bedrock via the public AWS endpoint. There is no VPC-peering option for Cloudflare Workers → AWS today (as of plan authoring). If that posture changes (e.g. private link), revisit.

## 6. Pre-merge checklist for the Bedrock-onboarding PR

When the PR that actually turns Bedrock on is opened, this checklist should be reviewed:

- [ ] §3a redaction control is still active (Pester regression green; no regressions on `Tests/Shared/Redact-Secrets.Tests.ps1`).
- [ ] §3b allowlist contains exactly the Bedrock regional endpoint with trailing `/` (no other entries).
- [ ] `env.AI_TUNNEL_URL` Cloudflare secret matches the allowlist entry exactly.
- [ ] §4a decision documented: WormCatcher-only OR Axios redactor extended.
- [ ] §5a–§5e AWS-side controls verified by security / cloud team.
- [ ] Rollback plan: `wrangler secret delete AI_TUNNEL_URL` reverts to the fail-closed state instantly.

## 7. Review checkpoints

This document should be re-reviewed when:

- A new finder is added that emits free-form content under a key not in the §3a whitelist (add the key OR add a redactor call at the new emission site).
- A new credential format gains adoption that doesn't fit the §3a pattern set.
- Bedrock's contractual posture (§2) changes.
- The dashboard schema starts storing additional finding content beyond `finding.detail.slice(0, 500)`.

---

**Authoring trace:** Drafted from `~/.claude/plans/please-write-a-update-tidy-jellyfish.md` Part 3. Engineering controls landed on `feature/wormcatcher-bounded-detection` PR #2. Last reviewed 2026-05-21.
