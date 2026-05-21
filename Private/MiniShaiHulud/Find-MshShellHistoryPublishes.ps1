function Find-MshShellHistoryPublishes {
    <#
    .SYNOPSIS
        Mini Shai-Hulud check 12 — 'npm publish' events in shell history during
        the attack window.
    .DESCRIPTION
        Reads bash/zsh/PowerShell history files and surfaces any 'npm publish'
        lines. We cannot reliably timestamp every shell-history line (bash
        history doesn't store timestamps by default), so when timestamps are
        unavailable we emit the finding as High but mark in the description
        that timing could not be confirmed. zsh extended history and PSReadline
        history both carry timestamps — those entries are filtered to the
        attack window.
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
    function _InWindow { param([datetime]$t)
        $tU = $t.ToUniversalTime()
        if ($attackStart -and $tU -lt $attackStart) { return $false }
        if ($attackEnd   -and $tU -gt $attackEnd)   { return $false }
        return $true
    }

    $sources = @()

    # bash / zsh — POSIX history files
    foreach ($f in @('.bash_history', '.zsh_history')) {
        $p = Join-Path $HOME $f
        if (Test-Path $p) { $sources += [PSCustomObject]@{ Path = $p; Kind = $f } }
    }

    # PowerShell readline history
    try {
        $psHist = (Get-PSReadLineOption).HistorySavePath
        if ($psHist -and (Test-Path $psHist)) {
            $sources += [PSCustomObject]@{ Path = $psHist; Kind = 'psreadline' }
        }
    } catch { }

    foreach ($src in $sources) {
        try {
            $lines = Get-Content $src.Path -ErrorAction Stop
        } catch { continue }

        foreach ($line in $lines) {
            if ([string]::IsNullOrEmpty($line)) { continue }
            if ($line -notmatch '\bnpm\s+publish\b') { continue }

            # Try to extract a timestamp for zsh extended-history lines: ": 1714581234:0;npm publish ..."
            $whenStr = ''
            $ok = $true
            if ($src.Kind -eq '.zsh_history' -and $line -match '^:\s*(\d+):\d+;') {
                try {
                    $epoch = [int64]$matches[1]
                    $when  = [datetimeoffset]::FromUnixTimeSeconds($epoch).UtcDateTime
                    $ok = _InWindow $when
                    $whenStr = $when.ToString('s') + 'Z'
                } catch { }
            }

            if (-not $ok) { continue }

            $findings += New-Finding `
                -Type 'ShellPublish' `
                -Severity 'High' `
                -Description $(if ($whenStr) {
                    "Shell history shows 'npm publish' at $whenStr — confirm whether this user normally publishes from this machine."
                } else {
                    "Shell history shows 'npm publish' (timestamp unavailable for $($src.Kind) — could not filter to attack window). Confirm whether this user normally publishes from this machine."
                }) `
                -Path $src.Path `
                -Extra @{
                    Command = $line
                    When    = $whenStr
                    Source  = $src.Kind
                }
        }
    }

    return ,$findings
}
