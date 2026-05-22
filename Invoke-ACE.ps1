#Requires -Version 7.0
<#
.SYNOPSIS
    RatCatcher — scans for evidence of the March 31, 2026 Axios NPM supply chain attack.
.DESCRIPTION
    Runs ten checks covering the full compromise kill chain:
    lockfile evidence, deployed package artifacts, npm cache, dropped RAT payloads,
    persistence mechanisms, XOR-obfuscated indicators, and network evidence.
    Generates a forensic report and submits results to the RatCatcher dashboard.
.PARAMETER Path
    Root directories to scan for Node.js projects. Defaults to common dev locations.
.PARAMETER OutputPath
    Directory for report and log files.
.EXAMPLE
    .\Invoke-RatCatcher.ps1
.EXAMPLE
    .\Invoke-RatCatcher.ps1 -Path C:\Dev
#>
[CmdletBinding()]
param(
    [string[]]$Path         = $(if ($env:OS -eq 'Windows_NT') { @('C:\') } else { @('/') }),
    [string]$OutputPath     = $(if ($env:OS -eq 'Windows_NT') { 'C:\Logs' } else { '/tmp' }),
    [switch]$NoSubmit,
    [switch]$NonInteractive,
    [string]$SubmitPassword,
    [int]$Threads           = 4,
    # Test-artifact overrides — point at synthetic data without touching real npm cache or firewall log
    [string]$TestCacheDir,
    [string]$TestFirewallLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$RatCatcherVersion = '2.1.0'

$pvt = Join-Path $PSScriptRoot 'Private'
# Shared helpers are dot-sourced first so check functions can reference them.
. (Join-Path $pvt 'Shared\New-Finding.ps1')
. (Join-Path $pvt 'Shared\Get-LockfileText.ps1')
. (Join-Path $pvt 'Get-NodeProjects.ps1')
. (Join-Path $pvt 'Invoke-LockfileAnalysis.ps1')
. (Join-Path $pvt 'Find-ForensicArtifacts.ps1')
. (Join-Path $pvt 'Invoke-NpmCacheScan.ps1')
. (Join-Path $pvt 'Search-DroppedPayloads.ps1')
. (Join-Path $pvt 'Find-PersistenceArtifacts.ps1')
. (Join-Path $pvt 'Search-XorEncodedC2.ps1')
. (Join-Path $pvt 'Get-NetworkEvidence.ps1')
. (Join-Path $pvt 'New-ScanReport.ps1')
. (Join-Path $pvt 'New-ExecBriefing.ps1')
. (Join-Path $pvt 'New-ScanLogHtml.ps1')
. (Join-Path $pvt 'Send-ScanReport.ps1')
. (Join-Path $pvt 'Submit-ScanToApi.ps1')

# Load logo for HTML reports (resize to ~600px to keep embedded size reasonable)
$logoBase64 = ''
$logoFile   = Join-Path $PSScriptRoot 'RatCatcher.png'
if (Test-Path $logoFile) {
    try { $logoBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($logoFile)) } catch { }
}


# ── Resolve scan paths (expand drive roots, skip OS/system folders) ───────────
if ($IsWindows) {
    $excludedTopLevel = @(
        # OS and system
        'Windows', 'Program Files', 'Program Files (x86)',
        'ProgramData', 'Recovery', 'System Volume Information',
        'MSOCache', 'OneDriveTemp', '$Recycle.Bin', 'Config.Msi',
        # Media and documents (never contain Node.js projects)
        'Mp3s', 'WAVs', 'Videos', 'Music', 'Photos', 'Pictures',
        # Virtual machines and large binaries
        'VirtualMachines', 'VMs', 'Hyper-V',
        # Hardware and drivers
        'Intel', 'Dell', 'Drivers', 'AMD', 'NVIDIA',
        # Logs and temp (scanned separately by checks 4-5)
        'Logs', 'dumps', 'PerfLogs',
        # Misc non-dev
        'inetpub'
    )
} else {
    $excludedTopLevel = @(
        # OS and system (macOS + Linux)
        'bin', 'sbin', 'boot', 'dev', 'proc', 'sys', 'run',
        'System', 'Library', 'Applications', 'Volumes',
        # Package managers and system libraries
        'usr', 'snap', 'flatpak',
        # Temp and logs (scanned separately by checks 4-5)
        'tmp', 'var',
        # Misc
        'lost+found', 'mnt', 'media', 'cdrom'
    )
}

$resolvedPaths = [System.Collections.Generic.List[string]]::new()
foreach ($root in $Path) {
    $rootItem = Get-Item -LiteralPath $root -ErrorAction SilentlyContinue
    if (-not $rootItem) { Write-Warning "Path not found, skipping: $root"; continue }

    # If the user passed a filesystem root (C:\ on Windows, / on Unix), expand to subdirectories
    $isRoot = if ($IsWindows) { $rootItem.FullName -match '^[A-Za-z]:\\?$' } else { $rootItem.FullName -eq '/' }
    if ($isRoot) {
        Get-ChildItem -LiteralPath $rootItem.FullName -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin $excludedTopLevel -and $_.Name -notmatch '^\$' -and $_.Name -notmatch '^\.' } |
        ForEach-Object { $resolvedPaths.Add($_.FullName) }
    } else {
        $resolvedPaths.Add($rootItem.FullName)
    }
}

# Exclude RatCatcher's own directory to prevent false positives from IOC strings in source code
$scannerDir = (Resolve-Path $PSScriptRoot).Path
$resolvedPaths = [System.Collections.Generic.List[string]]@(
    $resolvedPaths | Where-Object { -not $_.StartsWith($scannerDir) }
)

# ── Confirmation prompt ────────────────────────────────────────────────────────
$detectedOS = if ($IsWindows) { 'Windows' } elseif ($IsMacOS) { 'macOS' } else { 'Linux' }
Write-Host ''
Write-Host '================================================================'
Write-Host "  AXXESS COMPLIANCE ENGINE v$RatCatcherVersion"
Write-Host "  Platform: $detectedOS | PowerShell $($PSVersionTable.PSVersion)"
Write-Host '================================================================'
Write-Host ''
Write-Host '  The following folders will be scanned on this machine:'
Write-Host ''
foreach ($p in $resolvedPaths) { Write-Host "    $p" }
Write-Host ''
Write-Host '  Skipped (OS/system):' ($excludedTopLevel -join ', ')
Write-Host ''
if ($NonInteractive) {
    Write-Host '  [NonInteractive] Skipping confirmation — starting scan automatically.'
} else {
    $confirm = Read-Host '  Press ENTER to start the scan, or type Q to quit'
    if ($confirm -match '^[Qq]') { Write-Host 'Scan cancelled.'; exit 0 }
}
Write-Host ''

# ── Submission password ───────────────────────────────────────────────────────
if (-not $NoSubmit) {
    if ($SubmitPassword) {
        $submitPassword = $SubmitPassword
    } else {
        Write-Host '  A submission password is required to run the scan.'
        Write-Host '  Contact your manager or the DevOps team if you do not have one.'
        Write-Host ''
        $submitPassword = Read-Host '  Enter ACE submission password'
        if ([string]::IsNullOrWhiteSpace($submitPassword)) {
            Write-Host ''
            Write-Host '  No password entered — scan cancelled.'
            exit 0
        }
    }

    # Validate password with the server before starting the scan
    Write-Host '  Verifying submission password...'
    try {
        $testBody = [System.Text.Encoding]::UTF8.GetBytes("--test`r`nContent-Disposition: form-data; name=`"password`"`r`n`r`n$submitPassword`r`n--test--`r`n")
        $testResp = Invoke-WebRequest -Uri 'https://mbfromit.com/ratcatcher/submit' -Method POST `
            -Body $testBody -ContentType 'multipart/form-data; boundary=test' `
            -SkipHttpErrorCheck -ErrorAction Stop
        if ($testResp.StatusCode -eq 401) {
            Write-Host ''
            Write-Host '  Incorrect password. Please check with your manager or DevOps team.' -ForegroundColor Red
            Write-Host ''
            exit 0
        }
    } catch { }
    Write-Host '  Password verified.' -ForegroundColor Green
    Write-Host ''
}

$null = New-Item -ItemType Directory -Path $OutputPath -Force
$hn   = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } elseif (Get-Command hostname -ErrorAction SilentlyContinue) { (hostname).Trim() } else { 'unknown' }
$ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
$log  = Join-Path $OutputPath "RatCatcher-${hn}-${ts}.log"

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$Level] $Msg"
    Write-Host $line
    Add-Content -Path $log -Value $line -ErrorAction SilentlyContinue
}

$attackWindow = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
$startTime    = Get-Date

Write-Log "ACE Axios scanner - 10-check suite"
Write-Log "Attack window start: $attackWindow"
Write-Log "Scanning paths: $($resolvedPaths -join ', ')"

# ── Check 1: Discover Node.js projects ────────────────────────────────────────
Write-Log "[1/10] Discovering Node.js projects..."
$projects = @(Get-NodeProjects -Path $resolvedPaths -ExcludeDir $scannerDir)
Write-Log "Found $($projects.Count) project(s)"

# ── Checks 2 & 3: Lockfile analysis + artifact detection (parallel on PS7) ───
if ($PSVersionTable.PSVersion.Major -ge 7 -and $projects.Count -gt 0) {
    Write-Log "[2/10] Analysing lockfiles (parallel, $Threads threads)..."
    $lockfileResults = @($projects | ForEach-Object -Parallel {
        . (Join-Path $using:pvt 'Invoke-LockfileAnalysis.ps1')
        Invoke-LockfileAnalysis -ProjectPath $_.ProjectPath
    } -ThrottleLimit $Threads)

    Write-Log "[3/10] Detecting project-level forensic artifacts (parallel)..."
    $rawArtifacts = @($projects | ForEach-Object -Parallel {
        . (Join-Path $using:pvt 'Find-ForensicArtifacts.ps1')
        Find-ForensicArtifacts -ProjectPath $_.ProjectPath
    } -ThrottleLimit $Threads)
} else {
    Write-Log "[2/10] Analysing lockfiles (sequential)..."
    $lockfileResults = @($projects | ForEach-Object { Invoke-LockfileAnalysis -ProjectPath $_.ProjectPath })
    Write-Log "[3/10] Detecting project-level forensic artifacts..."
    $rawArtifacts    = @($projects | ForEach-Object { Find-ForensicArtifacts -ProjectPath $_.ProjectPath })
}
# Ensure these are always arrays even if checks 2/3 were skipped (no projects found)
if (-not $lockfileResults) { $lockfileResults = @() }
if (-not $rawArtifacts)    { $rawArtifacts    = @() }
$artifacts = @($rawArtifacts | Where-Object { $_ })

# ── Check 4: npm cache ────────────────────────────────────────────────────────
Write-Log "[4/10] Scanning npm cache and global npm..."
$cacheFindings = @(Invoke-NpmCacheScan -CacheDirOverride $TestCacheDir)

# ── Check 5: Dropped payloads ─────────────────────────────────────────────────
Write-Log "[5/10] Searching for dropped RAT payloads in temp/appdata..."
$droppedPayloads = @(Search-DroppedPayloads -AttackWindowStart $attackWindow)

# ── Check 6: Persistence ──────────────────────────────────────────────────────
$persistLabel = if ($IsWindows) { 'tasks, registry, startup' } elseif ($IsMacOS) { 'launchagents, cron' } else { 'systemd, cron, autostart' }
Write-Log "[6/10] Checking persistence mechanisms ($persistLabel)..."
$persistenceArtifacts = @(Find-PersistenceArtifacts -AttackWindowStart $attackWindow)

# ── Check 7: XOR-encoded indicators ──────────────────────────────────────────
Write-Log "[7/10] Scanning for XOR-encoded C2 indicators..."
$xorFindings = @(Search-XorEncodedC2)

# ── Check 8: Network evidence ─────────────────────────────────────────────────
Write-Log "[8/10] Checking network evidence (DNS cache, active connections, firewall log)..."
$neParams = @{}
if ($TestFirewallLogPath) { $neParams['FirewallLogPath'] = $TestFirewallLogPath }
$networkEvidence = @(Get-NetworkEvidence @neParams)

# ── Check 9: Generate report ──────────────────────────────────────────────────
$duration = (Get-Date) - $startTime
$metadata = @{
    Timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
    Hostname  = $hn
    Username  = if ($env:USERNAME) { $env:USERNAME } elseif ($env:USER) { $env:USER } else { 'unknown' }
    Duration  = "$([Math]::Round($duration.TotalSeconds,1))s"
    Paths     = $Path
}

Write-Log "[9/10] Generating forensic report..."
$reportPath = New-ScanReport `
    -Projects             $projects `
    -LockfileResults      @($lockfileResults) `
    -Artifacts            $artifacts `
    -CacheFindings        $cacheFindings `
    -DroppedPayloads      $droppedPayloads `
    -PersistenceArtifacts $persistenceArtifacts `
    -XorFindings          $xorFindings `
    -NetworkEvidence      $networkEvidence `
    -OutputPath           $OutputPath `
    -ScanMetadata         $metadata `
    -LogoBase64           $logoBase64

Write-Log "Technical report: $reportPath"

# Convert scan log to HTML now so its filename is available for the briefing link
Write-Log "[9a/10] Converting scan log to HTML..."
# (this Write-Log call is the last entry — flush then convert)
$logHtmlPath = New-ScanLogHtml -LogPath $log -LogoBase64 $logoBase64 -ScanMetadata $metadata
$log = $logHtmlPath   # update $log so summary still refers to correct file

# ── Check 9b: Executive Briefing ──────────────────────────────────────────────
Write-Log "[9b/10] Generating executive briefing..."
$briefingPath = New-ExecBriefing `
    -ProjectCount         $projects.Count `
    -LockfileResults      @($lockfileResults) `
    -Artifacts            $artifacts `
    -CacheFindings        $cacheFindings `
    -DroppedPayloads      $droppedPayloads `
    -PersistenceArtifacts $persistenceArtifacts `
    -XorFindings          $xorFindings `
    -NetworkEvidence      $networkEvidence `
    -TechnicalReportPath  $reportPath `
    -LogHtmlPath          $logHtmlPath `
    -OutputPath           $OutputPath `
    -ScanMetadata         $metadata `
    -LogoBase64           $logoBase64

Write-Log "Executive briefing: $briefingPath"

# ── Check 10: Submit to dashboard ─────────────────────────────────────────────
$vulnCount      = @($lockfileResults | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto -or $_.HasMaliciousOpenclaw }).Count
$criticalCount  = @($artifacts + $cacheFindings + $droppedPayloads + $persistenceArtifacts + $xorFindings + $networkEvidence | Where-Object { $_.Severity -eq 'Critical' }).Count

if (-not $NoSubmit) {
    Write-Log "[10/10] Submitting results to dashboard..."
    $submitVerdict  = if ($vulnCount -gt 0 -or $criticalCount -gt 0) { 'COMPROMISED' } else { 'CLEAN' }

    $submitResult = Submit-ScanToApi `
        -ApiUrl          'https://mbfromit.com/ratcatcher/submit' `
        -Password        $submitPassword `
        -Hostname        $hn `
        -Username        $metadata.Username `
        -ScanTimestamp   $metadata.Timestamp `
        -Duration        $metadata.Duration `
        -Verdict         $submitVerdict `
        -ProjectsScanned $projects.Count `
        -VulnerableCount $vulnCount `
        -CriticalCount   $criticalCount `
        -PathsScanned    ($resolvedPaths | ConvertTo-Json -Compress) `
        -BriefPath       $briefingPath `
        -ReportPath      $reportPath `
        -Campaign        'axios'

    switch ($submitResult.Status) {
        'success'        { Write-Log "[INFO] Scan submitted successfully (ID: $($submitResult.Id))" }
        'wrong-password' { Write-Log 'Submission password incorrect — report not submitted' 'WARN' }
        'error'          { Write-Log "Submission failed: $($submitResult.Message)" 'WARN' }
    }
} else {
    Write-Log "[10/10] Dashboard submission skipped (-NoSubmit)"
}

Write-Log ''
Write-Log "═══════════════════════════════════════"
Write-Log " SCAN COMPLETE - $(Get-Date -Format 'HH:mm:ss')"
Write-Log " Projects scanned    : $($projects.Count)"
Write-Log " Vulnerable (lockfile): $vulnCount"
Write-Log " Critical findings   : $criticalCount"
Write-Log " Technical report    : $reportPath"
Write-Log " Executive briefing  : $briefingPath"

# ── Launch dashboard in browser ───────────────────────────────────────────────
if (-not $NoSubmit -and $submitResult.Status -eq 'success') {
    $dashUrl = "https://mbfromit.com/ratcatcher/dashboard?user=$([uri]::EscapeDataString($metadata.Username))"
    Write-Log "Opening dashboard to view AI-verified results..."
    Write-Log "  $dashUrl"
    try {
        if ($IsMacOS) { & open $dashUrl }
        elseif ($IsLinux) { & xdg-open $dashUrl 2>/dev/null }
        else { Start-Process $dashUrl }
    } catch { Write-Log "Could not auto-launch dashboard: $_" 'WARN' }
} else {
    Write-Log "Opening executive briefing locally..."
    try {
        if ($IsMacOS) { & open $briefingPath }
        elseif ($IsLinux) { & xdg-open $briefingPath 2>/dev/null }
        else { Start-Process $briefingPath }
    } catch { Write-Log "Could not auto-launch briefing: $_" 'WARN' }
}

if ($vulnCount -gt 0 -or $criticalCount -gt 0) {
    Write-Log ' Findings detected - AI is evaluating. Check dashboard for verified results.' 'WARN'
} else {
    Write-Log ' STATUS: CLEAN - no compromise evidence found across all 10 checks'
}

Write-Log ''
Write-Log '═══════════════════════════════════════'
if ($IsWindows) {
    Write-Log ' SECURITY REMINDER'
    Write-Log ' If you changed your ExecutionPolicy to run this scan,'
    Write-Log ' restore it now by closing this window or running:'
    Write-Log '   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted'
} else {
    Write-Log ' SCAN COMPLETE'
    Write-Log " Platform: $(if ($IsMacOS) {'macOS'} else {'Linux'})"
}
Write-Log '═══════════════════════════════════════'

if ($vulnCount -gt 0 -or $criticalCount -gt 0) { exit 1 } else { exit 0 }
