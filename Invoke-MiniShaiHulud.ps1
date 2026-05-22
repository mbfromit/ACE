#Requires -Version 7.0
<#
.SYNOPSIS
    Mini Shai-Hulud scanner — workstation forensic check for the TeamPCP
    self-propagating npm supply-chain worm (April–May 2026 onward).
.DESCRIPTION
    Runs 12 checks for known workstation-observable artifacts: compromised
    package@version pairs in lockfiles / package.json / installed
    node_modules; suspicious postinstall scripts; Bun runtime with
    attack-window activity; npm cache hits; token-file atime; GitHub
    Actions runner artifacts; recent cache activity; DNS / connection
    residue to exfil hosts; npm publish events in shell history. Posts
    results to the Axxess Compliance Engine (ACE) dashboard with campaign='mini-shai-hulud'.

    Reports findings only — does NOT certify the machine is virus-free.
    Mini Shai-Hulud is polymorphic and the head of the campaign lives in
    CI runners and stolen npm tokens, not on workstations. Pair this
    scanner with token rotation and CI audit per the runbook.
.PARAMETER Path
    Root directory or directories to scan. When omitted (the default), the
    scanner runs Phase 1 discovery across all fixed AND removable drives
    (Windows) / $HOME + /opt + /srv + /Volumes/* (macOS) / $HOME + /opt +
    /srv + /media/* + /mnt/* (Linux). Supplying -Path narrows the scan to
    just those roots.
.PARAMETER ExcludeDrives
    Windows-only opt-out for specific drive letters (e.g. 'D','E'). Use
    this when you know a drive is pure media/backup with no code.
.PARAMETER IncludeNetworkDrives
    Off by default. Network drives are skipped because of unpredictable
    latency. Set to include mapped network drives in discovery.
.PARAMETER DiscoveryTimeoutSec
    Overall wall-clock cap for Phase 1 discovery. Default 300 (5 min).
    Per-drive cap is 180s and per-tree cap is 90s, hardcoded.
.PARAMETER OutputPath
    Directory for the technical report and exec briefing HTML files.
.PARAMETER NoSubmit
    Skip the dashboard submission step.
.PARAMETER NonInteractive
    Skip confirmation prompts; suitable for CI / automated runs.
.PARAMETER SubmitPassword
    Pass the submission password directly instead of prompting.
.PARAMETER Threads
    Reserved for future per-project parallelization. Currently unused.
.PARAMETER IocApiUrl
    Override the IOC feed URL (default is the production dashboard endpoint).
.PARAMETER NoIocNetwork
    Skip the network IOC fetch — use the bundled JSON instead.
.PARAMETER SkipNpmAudit
    Skip the per-project `npm audit` triage step. By default the scanner
    runs `npm audit --json` against every project that produced an IOC
    match and uses the result to mark wildcard-scope findings (e.g.
    @tanstack/*) as Cleared when the npm advisory database doesn't flag
    them. Pass this switch to skip the audit (saves wall-clock on big
    monorepos at the cost of dropping all wildcard findings to
    Inconclusive). The verdict-envelope work in
    docs/PLAN-wormcatcher-actionable-verdicts.md is the source of truth.
.EXAMPLE
    ./Invoke-MiniShaiHulud.ps1
    Scan default dev folders and submit results.
.EXAMPLE
    ./Invoke-MiniShaiHulud.ps1 -Path C:\Dev -NoSubmit
    Scan one folder, no upload (useful for offline machines).
#>
[CmdletBinding()]
param(
    # Default to empty so we drop into Phase 1 discovery (the new behavior).
    # Supplying -Path narrows discovery to those roots instead of replacing
    # it — the same deny-list, reparse-point skip, and time caps still apply.
    [string[]]$Path                  = @(),
    [string[]]$ExcludeDrives         = @(),
    [switch]$IncludeNetworkDrives,
    [int]$DiscoveryTimeoutSec        = 300,
    [string]$OutputPath              = $(if ($env:OS -eq 'Windows_NT') { 'C:\Logs' } else { '/tmp' }),
    [switch]$NoSubmit,
    [switch]$NonInteractive,
    [string]$SubmitPassword,
    [int]$Threads                    = 4,
    [string]$IocApiUrl               = 'https://mbfromit.com/ratcatcher/api/iocs/mini-shai-hulud',
    [switch]$NoIocNetwork,
    [string]$SubmitApiUrl            = 'https://mbfromit.com/ratcatcher/submit',
    [switch]$SkipNpmAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ScannerVersion = '1.0.0'

# ── Dot-source helpers ────────────────────────────────────────────────────────
$pvt = Join-Path $PSScriptRoot 'Private'
. (Join-Path $pvt 'Shared\New-Finding.ps1')
. (Join-Path $pvt 'Shared\Get-LockfileText.ps1')
. (Join-Path $pvt 'Get-NodeProjects.ps1')
. (Join-Path $pvt 'Submit-ScanToApi.ps1')
$msh = Join-Path $pvt 'MiniShaiHulud'
. (Join-Path $msh 'Get-MshIocs.ps1')
. (Join-Path $msh 'Find-MshDiscoveryRoots.ps1')
. (Join-Path $msh 'Invoke-MshNpmAudit.ps1')
. (Join-Path $msh 'Find-MshBadPackages.ps1')
. (Join-Path $msh 'Find-MshSuspiciousScripts.ps1')
. (Join-Path $msh 'Find-MshBunRuntime.ps1')
. (Join-Path $msh 'Invoke-MshNpmCacheScan.ps1')
. (Join-Path $msh 'Find-MshTokenTouches.ps1')
. (Join-Path $msh 'Find-MshRunnerArtifacts.ps1')
. (Join-Path $msh 'Find-MshRecentCacheActivity.ps1')
. (Join-Path $msh 'Get-MshNetworkEvidence.ps1')
. (Join-Path $msh 'Find-MshShellHistoryPublishes.ps1')
. (Join-Path $msh 'Find-MshWormWorkflow.ps1')
. (Join-Path $msh 'Find-MshPayloadFile.ps1')
. (Join-Path $msh 'Find-MshDropperArtifact.ps1')
. (Join-Path $msh 'Find-MshTrufflehogDrop.ps1')
. (Join-Path $msh 'New-MshScanReport.ps1')
. (Join-Path $msh 'New-MshExecBriefing.ps1')

# ── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
$startTime = Get-Date
$startUtc  = $startTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
$hn        = [System.Net.Dns]::GetHostName()
$user      = $env:USER; if (-not $user) { $user = $env:USERNAME }
function Write-Log {
    param([string]$msg, [string]$lvl = 'INFO')
    $ts = (Get-Date).ToString('HH:mm:ss')
    $color = switch ($lvl) { 'WARN'{'Yellow'}; 'ERROR'{'Red'}; 'OK'{'Green'}; default{'Gray'} }
    Write-Host "[$ts] $msg" -ForegroundColor $color
}

Write-Log "Axxess Compliance Engine - Mini Shai-Hulud scanner v$ScannerVersion" 'OK'
Write-Log "Host: $hn  User: $user  OutputPath: $OutputPath"

# ── Password handling ─────────────────────────────────────────────────────────
$submitPassword = $SubmitPassword
if (-not $NoSubmit -and -not $submitPassword) {
    if ($NonInteractive) {
        Write-Log 'NonInteractive set but no -SubmitPassword provided; disabling submission' 'WARN'
        $NoSubmit = $true
    } else {
        $sec = Read-Host -Prompt 'Submission password (blank to skip upload)' -AsSecureString
        $submitPassword = [System.Net.NetworkCredential]::new('', $sec).Password
        if (-not $submitPassword) { $NoSubmit = $true; Write-Log 'No password entered — running without submission' 'WARN' }
    }
}

# ── Load IOC bundle ───────────────────────────────────────────────────────────
Write-Log 'Loading Mini Shai-Hulud IOC bundle...'
$iocs = Get-MshIocs -ApiUrl $IocApiUrl -NoNetwork:$NoIocNetwork
Write-Log "IOC source: $($iocs.source); updated_at: $($iocs.updated_at); packages: $(@($iocs.packages).Count)" $(
    if ($iocs.source -eq 'fallback-hardcoded') { 'WARN' } else { 'OK' })

# ── Phase 1: bounded discovery ────────────────────────────────────────────────
# Find candidate roots (git repos + Node projects) anywhere on this workstation
# that could host a Tier-1 IOC. Replaces the old hardcoded USERPROFILE list and
# the unbounded Get-NodeProjects walk. The function self-bounds with per-tree,
# per-drive, and overall wall-clock caps.
$userSuppliedPath = $Path -and $Path.Count -gt 0
Write-Log '[Phase 1] Bounded discovery walk...'
$discoveryParams = @{
    DiscoveryTimeoutSec = $DiscoveryTimeoutSec
}
if ($userSuppliedPath)        { $discoveryParams['Path']                 = $Path }
if ($ExcludeDrives.Count -gt 0) { $discoveryParams['ExcludeDrives']      = $ExcludeDrives }
if ($IncludeNetworkDrives)    { $discoveryParams['IncludeNetworkDrives'] = $true }

$discoveryResult = Find-MshDiscoveryRoots @discoveryParams
$rootCount     = @($discoveryResult.Roots).Count
$gitRoots      = @($discoveryResult.Roots | Where-Object { $_.Type -in 'git_repo','both' })
$nodeRoots     = @($discoveryResult.Roots | Where-Object { $_.Type -in 'node_project','both' })

Write-Log ("Discovery: {0} roots in {1}s ({2} git, {3} node) across {4} drive(s); skipped {5} dirs by deny-list" -f `
    $rootCount, $discoveryResult.DurationSec, $gitRoots.Count, $nodeRoots.Count,
    @($discoveryResult.ScannedDrives).Count, $discoveryResult.SkippedCounts.DenyList) $(
    if ($rootCount -eq 0) { 'WARN' } else { 'OK' })
if ($discoveryResult.HitOverallCap)           { Write-Log 'Discovery overall cap fired — some drives partial-scanned.' 'WARN' }
if (@($discoveryResult.PartialDrives).Count) { Write-Log "Partial-scanned drives: $(@($discoveryResult.PartialDrives | ForEach-Object { $_.Drive }) -join ', ')" 'WARN' }

# Transition safety: if discovery yielded zero roots AND the user didn't
# supply -Path, fall back to the old USERPROFILE list and walk it directly.
# This keeps the scanner useful on weird environments (locked-down boxes,
# AppLocker, WMI broken, etc.) where the new walker can't see anything.
$fallbackPathsUsed = @()
if ($rootCount -eq 0 -and -not $userSuppliedPath) {
    Write-Log 'Phase 1 yielded zero roots; falling back to legacy USERPROFILE walk for transition safety.' 'WARN'
    $fallbackPathsUsed = if ($env:OS -eq 'Windows_NT') {
        @("$env:USERPROFILE\Dev", "$env:USERPROFILE\source", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Projects") |
            Where-Object { Test-Path $_ }
    } else {
        @("$HOME/dev", "$HOME/src", "$HOME/code", "$HOME/projects", "$HOME/Documents") |
            Where-Object { Test-Path $_ }
    }
    foreach ($fp in $fallbackPathsUsed) {
        try {
            $found = Get-NodeProjects -Path $fp
            if ($found) {
                $nodeRoots += @($found | ForEach-Object { [PSCustomObject]@{ Path = $_.ProjectPath; Type = 'node_project'; Drive = '(legacy)' } })
            }
        } catch { Write-Log "Legacy project walk failed for ${fp}: $_" 'WARN' }
    }
    Write-Log "Legacy walk recovered $(@($nodeRoots).Count) node projects."
}

# Build $projects in the shape downstream checks expect ({ ProjectPath, ... })
$projects = @($nodeRoots | ForEach-Object { [PSCustomObject]@{ ProjectPath = $_.Path } })
$resolvedPaths = @($discoveryResult.Roots | ForEach-Object { $_.Path })
if ($fallbackPathsUsed.Count -gt 0) { $resolvedPaths = $fallbackPathsUsed }
Write-Log "Proceeding to surgical IOC probes against $($projects.Count) Node project(s) and $($gitRoots.Count) git repo(s)."

# ── Findings accumulator ──────────────────────────────────────────────────────
# Plain array + assignment pattern (not += inside the loop, which is O(n^2) on
# big result sets). Each check returns an array of findings; we concat with the
# unary-comma + Where-Object pattern that survives PowerShell's strict-mode
# array unwrapping. $allFindings ends up as a flat [PSCustomObject[]].
$allFindings = @()

function Add-Findings { param($Result)
    if ($null -eq $Result) { return }
    foreach ($f in @($Result)) {
        if ($null -ne $f) { $script:allFindings += $f }
    }
}

# ── Checks 2/3/4: bad-package detection ───────────────────────────────────────
Write-Log '[2-4/16] Bad-package detection (lockfile / manifest / installed)...'
foreach ($proj in $projects) {
    try {
        Add-Findings (Find-MshBadPackages -ProjectPath $proj.ProjectPath -Iocs $iocs -SkipNpmAudit:$SkipNpmAudit)
    } catch { Write-Log "BadPackages check failed for $($proj.ProjectPath): $_" 'WARN' }
}

# ── Check 5: suspicious install scripts ───────────────────────────────────────
Write-Log '[5/16] Suspicious postinstall/preinstall scripts...'
foreach ($proj in $projects) {
    try {
        Add-Findings (Find-MshSuspiciousScripts -ProjectPath $proj.ProjectPath -Iocs $iocs)
    } catch { Write-Log "SuspiciousScripts check failed for $($proj.ProjectPath): $_" 'WARN' }
}

# ── Check 6: Bun runtime ──────────────────────────────────────────────────────
Write-Log '[6/16] Bun runtime presence + recent activity...'
try { Add-Findings (Find-MshBunRuntime -Iocs $iocs) }
catch { Write-Log "BunRuntime check failed: $_" 'WARN' }

# ── Check 7: npm cache ────────────────────────────────────────────────────────
Write-Log '[7/16] npm cache + global npm IOC scan...'
try { Add-Findings (Invoke-MshNpmCacheScan -Iocs $iocs) }
catch { Write-Log "NpmCacheScan check failed: $_" 'WARN' }

# ── Check 8: token-file atime ─────────────────────────────────────────────────
Write-Log '[8/16] Token-file atime in attack window...'
try { Add-Findings (Find-MshTokenTouches -Iocs $iocs) }
catch { Write-Log "TokenTouches check failed: $_" 'WARN' }

# ── Check 9: GHA runner artifacts ─────────────────────────────────────────────
Write-Log '[9/16] GitHub Actions runner artifacts...'
try { Add-Findings (Find-MshRunnerArtifacts) }
catch { Write-Log "RunnerArtifacts check failed: $_" 'WARN' }

# ── Check 10: recent cache activity ───────────────────────────────────────────
Write-Log '[10/16] Recent cache activity in attack window...'
try { Add-Findings (Find-MshRecentCacheActivity -Iocs $iocs) }
catch { Write-Log "RecentCacheActivity check failed: $_" 'WARN' }

# ── Check 11: network evidence ────────────────────────────────────────────────
Write-Log '[11/16] DNS cache + active connections vs exfil endpoints...'
try { Add-Findings (Get-MshNetworkEvidence -Iocs $iocs) }
catch { Write-Log "NetworkEvidence check failed: $_" 'WARN' }

# ── Check 12: shell history npm publish ───────────────────────────────────────
Write-Log '[12/16] Shell history npm publish events...'
try { Add-Findings (Find-MshShellHistoryPublishes -Iocs $iocs) }
catch { Write-Log "ShellHistoryPublishes check failed: $_" 'WARN' }

# ── Check 13: worm CI-persistence workflow file (Tier-1 IOC) ──────────────────
Write-Log "[13/16] Tier-1: worm workflow file at $($gitRoots.Count) git repo(s)..."
foreach ($g in $gitRoots) {
    try { Add-Findings (Find-MshWormWorkflow -GitRoot $g.Path -Iocs $iocs) }
    catch { Write-Log "WormWorkflow check failed at $($g.Path): $_" 'WARN' }
}

# ── Check 14: payload file inside compromised node_modules (Tier-1 IOC) ───────
# Probe only exact-pinned IOC names — wildcard scopes (e.g. @tanstack/*) are
# covered by lockfile/manifest checks. Probing is constant-time per package.
$exactPinnedPackages = @($iocs.packages | Where-Object { $_.name -and (-not $_.name.Contains('*')) } | ForEach-Object { $_.name })
Write-Log "[14/16] Tier-1: payload file probe at $($projects.Count) project(s) x $($exactPinnedPackages.Count) pinned IOC name(s)..."
foreach ($proj in $projects) {
    try { Add-Findings (Find-MshPayloadFile -NodeProjectRoot $proj.ProjectPath -MatchedPackages $exactPinnedPackages -Iocs $iocs) }
    catch { Write-Log "PayloadFile check failed at $($proj.ProjectPath): $_" 'WARN' }
}

# ── Check 15: dropper artifact (processor.sh) — Tier-1 IOC ────────────────────
Write-Log '[15/16] Tier-1: dropper artifact probe at temp / home / project roots...'
try { Add-Findings (Find-MshDropperArtifact -NodeProjectRoots @($projects | ForEach-Object { $_.ProjectPath }) -Iocs $iocs) }
catch { Write-Log "DropperArtifact check failed: $_" 'WARN' }

# ── Check 16: TruffleHog drop in unexpected location ──────────────────────────
Write-Log '[16/16] Tier-1: TruffleHog drop probe at known drop paths...'
try { Add-Findings (Find-MshTrufflehogDrop -Iocs $iocs) }
catch { Write-Log "TrufflehogDrop check failed: $_" 'WARN' }

# ── Aggregate verdict + counts ────────────────────────────────────────────────
$allFindings = @($allFindings)
$criticalCount = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount     = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
$vulnCount     = @($allFindings | Where-Object { $_.Type -like 'BadPackage*' }).Count

# Per-finding ScannerVerdict counts drive the post-triage rollup (plan
# Phase E). Defensive: older finding-emitters that don't set the field
# get counted nowhere — they keep their old severity-based weight via
# the Critical/High counts above, which is the safe behavior.
$findingsWithVerdict = @($allFindings | Where-Object {
    $_.PSObject.Properties.Name -contains 'ScannerVerdict' -and $_.ScannerVerdict
})
$confirmedCount    = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Confirmed'    }).Count
$clearedCount      = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Cleared'      }).Count
$inconclusiveCount = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Inconclusive' }).Count
$actionRequiredCount = @($findingsWithVerdict | Where-Object {
    $_.PSObject.Properties.Name -contains 'ActionRequired' -and $_.ActionRequired
}).Count

# Four-state local verdict. Plan Phase E rules:
#   COMPROMISED  — any Confirmed finding (post-triage match)
#   REVIEW       — no Confirmed, but ≥1 Inconclusive with an ActionRequired
#                  (manager needs to chase someone to resolve it)
#   INCONCLUSIVE — Phase 1 discovery saw zero roots AND no -Path
#                  (we didn't scan anything; cannot honestly say CLEAN)
#   CLEAN        — everything else: zero Confirmed, no actionable
#                  Inconclusive; whatever findings exist are Cleared or
#                  non-blocking Inconclusive
$noRootsDiscovered = ($rootCount -eq 0 -and $fallbackPathsUsed.Count -eq 0 -and -not $userSuppliedPath)

$localVerdict = if ($confirmedCount -gt 0) {
    'COMPROMISED'
} elseif ($actionRequiredCount -gt 0) {
    'REVIEW'
} elseif ($noRootsDiscovered) {
    'INCONCLUSIVE'
} else {
    'CLEAN'
}

# Server-side verdict stays two-state for back-compat with the dashboard's
# existing SQL. Now keyed off Confirmed-or-actionable instead of raw
# Critical/High, so wildcard noise that npm audit cleared no longer
# triggers the dashboard's manager workflow.
$submitVerdict = if ($confirmedCount -gt 0 -or $actionRequiredCount -gt 0) { 'COMPROMISED' } else { 'CLEAN' }

$logLevel = switch ($localVerdict) { 'COMPROMISED' {'ERROR'} 'REVIEW' {'WARN'} 'INCONCLUSIVE' {'WARN'} default {'OK'} }
Write-Log ("Verdict: $localVerdict (findings: $($allFindings.Count); " +
           "Confirmed: $confirmedCount; Cleared: $clearedCount; " +
           "Inconclusive: $inconclusiveCount; Action items: $actionRequiredCount)") $logLevel
if ($localVerdict -eq 'REVIEW') {
    Write-Log "  Note: REVIEW = no confirmed worm artifacts, but $actionRequiredCount finding(s) need user/manager action to resolve (e.g. install npm, fix lockfile, ask user about TruffleHog at unusual path)." 'INFO'
    Write-Log "  Open the brief's Action Items section — each card has a copy-paste instruction to forward." 'INFO'
}
if ($localVerdict -eq 'INCONCLUSIVE') {
    Write-Log "  Note: INCONCLUSIVE = Phase 1 discovery saw no Node projects or git repos. We cannot honestly declare this machine clean — we didn't scan anything." 'WARN'
    Write-Log "  Retry with -Path pointing at where code lives on this box (e.g. -Path 'C:\Atriora','D:\Repos')." 'INFO'
}
if ($localVerdict -eq 'CLEAN' -and $clearedCount -gt 0) {
    Write-Log "  Note: CLEAN reflects post-triage. $clearedCount watchlist match(es) cleared by npm advisory database." 'INFO'
}

# ── Render reports ────────────────────────────────────────────────────────────
$endTime = Get-Date
$durationS = "{0:N1}s" -f ($endTime - $startTime).TotalSeconds
$meta = @{
    Hostname            = $hn
    Username            = $user
    Timestamp           = $startUtc
    Duration            = $durationS
    ScannerVersion      = $ScannerVersion
    DiscoveryDiag       = $discoveryResult
    FallbackUsed        = ($fallbackPathsUsed.Count -gt 0)
    UserSuppliedPath    = $userSuppliedPath
    # Per-finding-verdict rollup — consumed by report templates in commit #6
    # to drive the post-triage headline ("3 confirmed Tier-1, 62 cleared by
    # npm audit" instead of "65 Critical, 31 High").
    ConfirmedCount      = $confirmedCount
    ClearedCount        = $clearedCount
    InconclusiveCount   = $inconclusiveCount
    ActionRequiredCount = $actionRequiredCount
    NpmAuditSkipped     = [bool]$SkipNpmAudit
}
Write-Log 'Generating technical report and executive briefing...'
$techPath  = New-MshScanReport    -Findings $allFindings -OutputPath $OutputPath -ScanMetadata $meta -Iocs $iocs -Verdict $localVerdict
$briefPath = New-MshExecBriefing  -Findings $allFindings -OutputPath $OutputPath -ScanMetadata $meta -Iocs $iocs -TechnicalReportPath $techPath -Verdict $localVerdict
Write-Log "Reports: $techPath" 'OK'
Write-Log "         $briefPath" 'OK'

# ── Submit ────────────────────────────────────────────────────────────────────
if (-not $NoSubmit -and $submitPassword) {
    Write-Log 'Submitting to dashboard...'
    $result = Submit-ScanToApi `
        -ApiUrl          $SubmitApiUrl `
        -Password        $submitPassword `
        -Hostname        $hn `
        -Username        $user `
        -ScanTimestamp   $startUtc `
        -Duration        $durationS `
        -Verdict         $submitVerdict `
        -ProjectsScanned $projects.Count `
        -VulnerableCount $vulnCount `
        -CriticalCount   $criticalCount `
        -PathsScanned    ($resolvedPaths | ConvertTo-Json -Compress) `
        -BriefPath       $briefPath `
        -ReportPath      $techPath `
        -Campaign        'mini-shai-hulud'

    switch ($result.Status) {
        'success'        { Write-Log "Submitted successfully (id: $($result.Id))" 'OK' }
        'wrong-password' { Write-Log 'Submission password rejected by server' 'WARN' }
        'skipped'        { Write-Log 'Submission skipped (no password)' 'WARN' }
        default          { Write-Log "Submission error: $($result.Message)" 'ERROR' }
    }
} else {
    Write-Log 'Skipping dashboard submission (NoSubmit or no password)' 'WARN'
}

# ── Exit ──────────────────────────────────────────────────────────────────────
# Exit 1 ONLY on COMPROMISED (≥1 ScannerVerdict=Confirmed finding). REVIEW
# returns 0 so it does not break CI gates — Inconclusive findings with
# ActionRequired are about user/manager workflow, not a confirmed incident.
# The runbook documents this contract.
Write-Log "Total duration: $durationS"
if ($localVerdict -eq 'COMPROMISED') { exit 1 } else { exit 0 }
