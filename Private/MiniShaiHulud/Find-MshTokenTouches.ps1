function Find-MshTokenTouches {
    <#
    .SYNOPSIS
        Mini Shai-Hulud check 8 — token-file last-access times inside attack window.
    .DESCRIPTION
        The worm harvests these specific files for token theft. We compare each
        file's LastAccessTime to the attack window. Atime is unreliable on:
            - Windows volumes (disabled by default since the NTFS atime tweak)
            - Unix mounts with the 'noatime' or 'relatime' option
        We always emit corroborating evidence rather than standalone proof. The
        finding's Description tells the reader to treat atime cautiously.
    .OUTPUTS
        Findings of Type 'TokenTouch', Severity High. One per file matched.
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

    # Token file locations. Glob expansion happens per-entry so we capture all
    # ~/.ssh/id_* private keys (not the .pub siblings).
    $targets = @(
        Join-Path $HOME '.npmrc'
        Join-Path $HOME '.docker/config.json'
        Join-Path $HOME '.config/gh/hosts.yml'
        Join-Path $HOME '.aws/credentials'
        Join-Path $HOME '.aws/config'
        Join-Path $HOME '.gitconfig'
        Join-Path $HOME '.netrc'
    )
    $sshDir = Join-Path $HOME '.ssh'
    if (Test-Path $sshDir) {
        try {
            $targets += @(Get-ChildItem -Path $sshDir -Filter 'id_*' -File -ErrorAction SilentlyContinue |
                Where-Object { -not $_.Name.EndsWith('.pub') } |
                ForEach-Object { $_.FullName })
        } catch { }
    }

    foreach ($p in $targets) {
        if (-not (Test-Path $p)) { continue }
        try {
            $f = Get-Item $p -ErrorAction Stop
            $atime = $f.LastAccessTime.ToUniversalTime()
            if ($atime -lt $attackStart) { continue }
            if ($attackEnd -and $atime -gt $attackEnd) { continue }

            $findings += New-Finding `
                -Type 'TokenTouch' `
                -Severity 'High' `
                -Description "Token file last-accessed inside Mini Shai-Hulud attack window ($($atime.ToString('s'))Z). Atime is unreliable when disabled by the OS — treat as corroborating evidence, not standalone proof." `
                -Path $p `
                -Extra @{
                    LastAccessTime = $f.LastAccessTime
                    LastWriteTime  = $f.LastWriteTime
                    Size           = $f.Length
                }
        } catch { }
    }

    return ,$findings
}
