function Find-MshTrufflehogDrop {
    <#
    .SYNOPSIS
        Mini Shai-Hulud Check 16 — TruffleHog binary dropped in unexpected
        location for credential-theft staging.
    .DESCRIPTION
        The Shai-Hulud worm downloads TruffleHog (or a renamed variant) to
        scrape secrets from the developer workstation. A `trufflehog` /
        `trufflehog.exe` binary at one of the IOC feed's
        `trufflehog_drop_paths` is a strong signal.

        Severity is conditional on the attack window:
            - mtime falls inside the attack window → Critical (confirmed
              credential-theft activity)
            - mtime outside the window → High (TruffleHog at an unusual
              path; a developer could have installed it there but it's
              not a common location)

        A user with TruffleHog installed via `brew install trufflehog` or
        `winget install` will see the binary on PATH but NOT at these
        specific drop paths, so this check won't false-positive on
        legitimate installs.

    .PARAMETER Iocs
        IOC bundle. Reads `trufflehog_drop_paths` and `attack_window_start`/
        `attack_window_end`. Defaults if the feed omits them.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Iocs)

    $findings = @()

    $rawPaths = @()
    if ($Iocs.PSObject.Properties['trufflehog_drop_paths']) {
        $rawPaths = @($Iocs.trufflehog_drop_paths | Where-Object { $_ })
    }
    if ($rawPaths.Count -eq 0) {
        $rawPaths = @(
            '/tmp/trufflehog'
            '~/Downloads/trufflehog'
            '~/.npm/_cacache/trufflehog'
        )
    }

    # Parse attack window once
    $attackStart = $null; $attackEnd = $null
    if ($Iocs.PSObject.Properties['attack_window_start'] -and $Iocs.attack_window_start) {
        try { $attackStart = [datetime]::Parse($Iocs.attack_window_start).ToUniversalTime() } catch { }
    }
    if ($Iocs.PSObject.Properties['attack_window_end'] -and $Iocs.attack_window_end) {
        try { $attackEnd = [datetime]::Parse($Iocs.attack_window_end).ToUniversalTime() } catch { }
    }

    foreach ($rp in $rawPaths) {
        $expanded = $rp -replace '^~', $HOME
        # On Windows, also probe the .exe variant of any extensionless path
        $candidates = @($expanded)
        if ($IsWindows -or $env:OS -eq 'Windows_NT') {
            if (-not [IO.Path]::HasExtension($expanded)) {
                $candidates += ($expanded + '.exe')
            }
        }

        foreach ($candidate in $candidates) {
            if (-not (Test-Path -LiteralPath $candidate)) { continue }

            $fi = Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue
            if (-not $fi -or $fi.PSIsContainer) { continue }

            $mtimeUtc = $fi.LastWriteTime.ToUniversalTime()
            $inWindow = $true
            if ($attackStart -and $mtimeUtc -lt $attackStart) { $inWindow = $false }
            if ($attackEnd   -and $mtimeUtc -gt $attackEnd)   { $inWindow = $false }

            $severity = if ($inWindow) { 'Critical' } else { 'High' }
            $reason   = if ($inWindow) {
                'mtime falls inside the published attack window — confirmed credential-theft staging'
            } else {
                'TruffleHog binary at an unusual drop path; mtime outside attack window — review whether developer intentionally placed it here'
            }

            # Verdict envelope: in-window matches are Confirmed (Tier-1 IR
            # action). Out-of-window matches drop to Inconclusive — the
            # binary could be a legitimate dev install at an unusual path,
            # so the manager asks the user before escalating.
            if ($inWindow) {
                $verdict       = 'Confirmed'
                $verdictReason = "Tier-1 worm artifact — TruffleHog binary at unusual drop path '$candidate', mtime inside the published campaign attack window."
                $actionReq     = "Worm-specific artifact present on disk. IMMEDIATELY isolate this workstation from the network. Follow incident response in [WormCatcher runbook](docs/MINI-SHAI-HULUD-RUNBOOK.md): rotate all credentials, audit CI workflows, check git history for unauthorized commits."
                $actionTarget  = 'UserAndManager'
            } else {
                $verdict       = 'Inconclusive'
                $verdictReason = "TruffleHog binary at unusual drop path '$candidate' but mtime predates the published campaign attack window. Could be a legitimate developer install at a non-default location."
                $actionReq     = "TruffleHog binary at unusual path but mtime predates the campaign attack window. Could be a legitimate developer install at a non-default location. Ask user: 'Did you install TruffleHog at ``$candidate`` yourself?' If no, escalate."
                $actionTarget  = 'Manager'
            }

            $findings += New-Finding `
                -Type 'TrufflehogDrop' `
                -Severity $severity `
                -Description ("TruffleHog binary present at $candidate — $reason.") `
                -Path $candidate `
                -Extra @{
                    SizeBytes            = $fi.Length
                    LastWriteTime        = $fi.LastWriteTime
                    InAttackWindow       = $inWindow
                    ScannerVerdict       = $verdict
                    ScannerVerdictReason = $verdictReason
                    ActionRequired       = $actionReq
                    ActionTarget         = $actionTarget
                }
        }
    }

    return $findings
}
