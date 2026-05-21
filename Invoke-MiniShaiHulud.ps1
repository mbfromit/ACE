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
    results to the RatCatcher dashboard with campaign='mini-shai-hulud'.

    Reports findings only — does NOT certify the machine is virus-free.
    Mini Shai-Hulud is polymorphic and the head of the campaign lives in
    CI runners and stolen npm tokens, not on workstations. Pair this
    scanner with token rotation and CI audit per the runbook.
.PARAMETER Path
    Root directory or directories to scan for Node.js projects.
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
.EXAMPLE
    ./Invoke-MiniShaiHulud.ps1
    Scan default dev folders and submit results.
.EXAMPLE
    ./Invoke-MiniShaiHulud.ps1 -Path C:\Dev -NoSubmit
    Scan one folder, no upload (useful for offline machines).
#>
[CmdletBinding()]
param(
    [string[]]$Path         = $(if ($env:OS -eq 'Windows_NT') {
        @("$env:USERPROFILE\Dev", "$env:USERPROFILE\source", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Projects") |
            Where-Object { Test-Path $_ }
    } else {
        @("$HOME/dev", "$HOME/src", "$HOME/code", "$HOME/projects", "$HOME/Documents") |
            Where-Object { Test-Path $_ }
    }),
    [string]$OutputPath     = $(if ($env:OS -eq 'Windows_NT') { 'C:\Logs' } else { '/tmp' }),
    [switch]$NoSubmit,
    [switch]$NonInteractive,
    [string]$SubmitPassword,
    [int]$Threads           = 4,
    [string]$IocApiUrl      = 'https://mbfromit.com/ratcatcher/api/iocs/mini-shai-hulud',
    [switch]$NoIocNetwork,
    [string]$SubmitApiUrl   = 'https://mbfromit.com/ratcatcher/submit'
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
. (Join-Path $msh 'Find-MshBadPackages.ps1')
. (Join-Path $msh 'Find-MshSuspiciousScripts.ps1')
. (Join-Path $msh 'Find-MshBunRuntime.ps1')
. (Join-Path $msh 'Invoke-MshNpmCacheScan.ps1')
. (Join-Path $msh 'Find-MshTokenTouches.ps1')
. (Join-Path $msh 'Find-MshRunnerArtifacts.ps1')
. (Join-Path $msh 'Find-MshRecentCacheActivity.ps1')
. (Join-Path $msh 'Get-MshNetworkEvidence.ps1')
. (Join-Path $msh 'Find-MshShellHistoryPublishes.ps1')
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

Write-Log "RatCatcher Mini Shai-Hulud scanner v$ScannerVersion" 'OK'
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

# ── Resolve scan paths ────────────────────────────────────────────────────────
$resolvedPaths = @($Path | Where-Object { $_ -and (Test-Path $_) })
if ($resolvedPaths.Count -eq 0) {
    Write-Log 'No scan paths exist — nothing to scan. Pass -Path to override.' 'WARN'
    $resolvedPaths = @()
}
Write-Log "Scan paths: $(($resolvedPaths -join ', '))"

# ── Check 1: discover projects ────────────────────────────────────────────────
Write-Log '[1/12] Discovering Node.js projects...'
$projects = @()
foreach ($p in $resolvedPaths) {
    try {
        $found = Get-NodeProjects -Path $p
        if ($found) { $projects += $found }
    } catch { Write-Log "Project discovery failed for ${p}: $_" 'WARN' }
}
Write-Log "Found $($projects.Count) Node.js projects"

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
Write-Log '[2-4/12] Bad-package detection (lockfile / manifest / installed)...'
foreach ($proj in $projects) {
    try {
        Add-Findings (Find-MshBadPackages -ProjectPath $proj.ProjectPath -Iocs $iocs)
    } catch { Write-Log "BadPackages check failed for $($proj.ProjectPath): $_" 'WARN' }
}

# ── Check 5: suspicious install scripts ───────────────────────────────────────
Write-Log '[5/12] Suspicious postinstall/preinstall scripts...'
foreach ($proj in $projects) {
    try {
        Add-Findings (Find-MshSuspiciousScripts -ProjectPath $proj.ProjectPath -Iocs $iocs)
    } catch { Write-Log "SuspiciousScripts check failed for $($proj.ProjectPath): $_" 'WARN' }
}

# ── Check 6: Bun runtime ──────────────────────────────────────────────────────
Write-Log '[6/12] Bun runtime presence + recent activity...'
try { Add-Findings (Find-MshBunRuntime -Iocs $iocs) }
catch { Write-Log "BunRuntime check failed: $_" 'WARN' }

# ── Check 7: npm cache ────────────────────────────────────────────────────────
Write-Log '[7/12] npm cache + global npm IOC scan...'
try { Add-Findings (Invoke-MshNpmCacheScan -Iocs $iocs) }
catch { Write-Log "NpmCacheScan check failed: $_" 'WARN' }

# ── Check 8: token-file atime ─────────────────────────────────────────────────
Write-Log '[8/12] Token-file atime in attack window...'
try { Add-Findings (Find-MshTokenTouches -Iocs $iocs) }
catch { Write-Log "TokenTouches check failed: $_" 'WARN' }

# ── Check 9: GHA runner artifacts ─────────────────────────────────────────────
Write-Log '[9/12] GitHub Actions runner artifacts...'
try { Add-Findings (Find-MshRunnerArtifacts) }
catch { Write-Log "RunnerArtifacts check failed: $_" 'WARN' }

# ── Check 10: recent cache activity ───────────────────────────────────────────
Write-Log '[10/12] Recent cache activity in attack window...'
try { Add-Findings (Find-MshRecentCacheActivity -Iocs $iocs) }
catch { Write-Log "RecentCacheActivity check failed: $_" 'WARN' }

# ── Check 11: network evidence ────────────────────────────────────────────────
Write-Log '[11/12] DNS cache + active connections vs exfil endpoints...'
try { Add-Findings (Get-MshNetworkEvidence -Iocs $iocs) }
catch { Write-Log "NetworkEvidence check failed: $_" 'WARN' }

# ── Check 12: shell history npm publish ───────────────────────────────────────
Write-Log '[12/12] Shell history npm publish events...'
try { Add-Findings (Find-MshShellHistoryPublishes -Iocs $iocs) }
catch { Write-Log "ShellHistoryPublishes check failed: $_" 'WARN' }

# ── Aggregate verdict + counts ────────────────────────────────────────────────
$allFindings = @($allFindings)
$criticalCount = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount     = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
$vulnCount     = @($allFindings | Where-Object { $_.Type -like 'BadPackage*' }).Count

# Three-state local verdict. COMPROMISED is reserved for findings that actually
# matched an IOC (Critical). High-only means corroborating evidence that needs
# a human glance but is not, by itself, an incident — check 8 (TokenTouch) and
# check 10 (RecentCacheActivity) are designed to be noisy and reliant on
# pairing with Critical findings for signal.
$localVerdict = if ($criticalCount -gt 0) {
    'COMPROMISED'
} elseif ($highCount -gt 0) {
    'REVIEW'
} else {
    'CLEAN'
}

# Server-side verdict stays two-state for back-compat with the dashboard's
# existing SQL. Any non-trivial finding goes to the dashboard as COMPROMISED so
# the manager workflow and AI verification engage.
$submitVerdict = if ($criticalCount -gt 0 -or $highCount -gt 0) { 'COMPROMISED' } else { 'CLEAN' }

$logLevel = switch ($localVerdict) { 'COMPROMISED' {'ERROR'} 'REVIEW' {'WARN'} default {'OK'} }
Write-Log "Verdict: $localVerdict (findings: $($allFindings.Count); Critical: $criticalCount; High: $highCount)" $logLevel
if ($localVerdict -eq 'REVIEW') {
    Write-Log "  Note: REVIEW = High findings but no IOC match. Most likely corroborating evidence (token-file atime, recent npm cache activity)." 'INFO'
    Write-Log "  Open the brief to inspect; pair with Critical findings to elevate." 'INFO'
}

# ── Render reports ────────────────────────────────────────────────────────────
$endTime = Get-Date
$durationS = "{0:N1}s" -f ($endTime - $startTime).TotalSeconds
$meta = @{
    Hostname  = $hn
    Username  = $user
    Timestamp = $startUtc
    Duration  = $durationS
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
# Exit 1 ONLY on COMPROMISED (Critical findings). REVIEW returns 0 so it does
# not break CI gates — High findings without IOC matches are corroborating
# evidence, not an incident. The runbook documents this contract.
Write-Log "Total duration: $durationS"
if ($localVerdict -eq 'COMPROMISED') { exit 1 } else { exit 0 }
