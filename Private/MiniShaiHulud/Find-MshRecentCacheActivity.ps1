function Find-MshRecentCacheActivity {
    <#
    .SYNOPSIS
        Mini Shai-Hulud check 10 — files modified inside the attack window
        under common npm / yarn / pnpm cache and log directories.
    .DESCRIPTION
        Surfaces install activity that happened during the window. Filenames
        are cross-referenced against the IOC package list when possible.
        Cap output at ~25 hits to avoid flooding the report for chatty caches.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Iocs)

    $findings = @()
    $attackStart = $null
    if ($Iocs.attack_window_start) {
        try { $attackStart = [datetime]::Parse($Iocs.attack_window_start).ToUniversalTime() } catch { }
    }
    if (-not $attackStart) { return ,$findings }
    $attackEnd = $null
    if ($Iocs.attack_window_end) {
        try { $attackEnd = [datetime]::Parse($Iocs.attack_window_end).ToUniversalTime() } catch { }
    }

    $roots = @(
        Join-Path $HOME '.npm/_logs'
        Join-Path $HOME '.yarn/cache'
        Join-Path $HOME '.local/share/pnpm/store'
    )

    # Build a fast match function over IOC package names (handles scope wildcards)
    function _NameMatches { param([string]$candidate)
        foreach ($p in $Iocs.packages) {
            $needle = $p.name
            if ($needle.EndsWith('/*')) { $needle = $needle.Substring(0, $needle.Length - 2) }
            if ($candidate -like "*$needle*") { return $true }
        }
        return $false
    }

    $emitted = 0
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        try {
            $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                if ($emitted -ge 25) { break }
                $mtime = $f.LastWriteTime.ToUniversalTime()
                if ($mtime -lt $attackStart) { continue }
                if ($attackEnd -and $mtime -gt $attackEnd) { continue }

                $matchesIoc = _NameMatches $f.FullName
                $severity = if ($matchesIoc) { 'Critical' } else { 'High' }

                $findings += New-Finding `
                    -Type 'RecentCacheActivity' `
                    -Severity $severity `
                    -Description $(if ($matchesIoc) {
                        "Cache activity inside attack window with IOC-package-matching filename: $($f.FullName)"
                    } else {
                        "Cache activity inside attack window (no name match) — corroborating evidence only: $($f.FullName)"
                    }) `
                    -Path $f.FullName `
                    -Extra @{
                        LastWriteTime = $f.LastWriteTime
                        MatchesIoc    = $matchesIoc
                        CacheRoot     = $root
                    }
                $emitted++
            }
        } catch { }
        if ($emitted -ge 25) { break }
    }

    return ,$findings
}
