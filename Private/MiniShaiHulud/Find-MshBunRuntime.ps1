function Find-MshBunRuntime {
    <#
    .SYNOPSIS
        Mini Shai-Hulud check 6 — Bun runtime presence + recent install activity.
    .DESCRIPTION
        The worm prefers Bun over Node specifically to dodge Node-targeted EDR.
        But many teams legitimately use Bun, so a bare 'bun on PATH' result is
        Informational only. We escalate to High when EITHER:
            - the bun binary's LastWriteTime falls inside the published attack window, OR
            - the user's ~/.bun/install/cache has files modified inside the
              attack window.
        Both are corroborating signals — a developer who normally uses Bun will
        still see install activity, but combined with a Confirmed BadPackage
        finding the AI verifier will rank this as a real signal.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Iocs)

    $findings = @()
    $attackStart = $null
    if ($Iocs.attack_window_start) {
        try { $attackStart = [datetime]::Parse($Iocs.attack_window_start).ToUniversalTime() } catch { }
    }
    $attackEnd = $null
    if ($Iocs.attack_window_end) {
        try { $attackEnd = [datetime]::Parse($Iocs.attack_window_end).ToUniversalTime() } catch { }
    }
    function _InWindow {
        param([datetime]$t)
        $tU = $t.ToUniversalTime()
        if ($attackStart -and $tU -lt $attackStart) { return $false }
        if ($attackEnd   -and $tU -gt $attackEnd)   { return $false }
        return $true
    }

    # Locate bun binary on PATH (skip Windows aliases that resolve to .ps1 wrappers)
    $bunCmd = Get-Command bun -ErrorAction SilentlyContinue | Where-Object { $_.CommandType -in 'Application','ExternalScript' } | Select-Object -First 1
    if (-not $bunCmd) { return ,$findings }

    $bunPath = $bunCmd.Source
    $bunFile = Get-Item $bunPath -ErrorAction SilentlyContinue
    if (-not $bunFile) { return ,$findings }

    $binInWindow = $false
    if ($bunFile.LastWriteTime) {
        $binInWindow = _InWindow $bunFile.LastWriteTime
    }

    # Check ~/.bun/install/cache for recent activity
    $bunCache = Join-Path $HOME '.bun/install/cache'
    $cacheActivity = @()
    if (Test-Path $bunCache) {
        try {
            $cacheActivity = @(Get-ChildItem -Path $bunCache -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { _InWindow $_.LastWriteTime } |
                Select-Object -First 10)
        } catch { }
    }

    $hasCacheActivity = $cacheActivity.Count -gt 0
    $severity = if ($binInWindow -or $hasCacheActivity) { 'High' } else { 'Informational' }

    $desc = if ($severity -eq 'High') {
        "Bun runtime present at $bunPath with attack-window activity" +
            $(if ($binInWindow)     { " (binary modified $($bunFile.LastWriteTime.ToString('s'))Z)" } else { '' }) +
            $(if ($hasCacheActivity){ ", $($cacheActivity.Count)+ recent install cache entries" }   else { '' })
    } else {
        "Bun runtime present at $bunPath. No attack-window activity detected — informational only. Bun has legitimate uses; ignore unless paired with other findings."
    }

    $findings += New-Finding `
        -Type 'BunRuntime' `
        -Severity $severity `
        -Description $desc `
        -Path $bunPath `
        -Extra @{
            LastWriteTime    = $bunFile.LastWriteTime
            BinaryInWindow   = $binInWindow
            CacheActivity    = $cacheActivity.Count
            CacheSample      = ($cacheActivity | Select-Object -First 3 -ExpandProperty FullName)
        }

    return ,$findings
}
