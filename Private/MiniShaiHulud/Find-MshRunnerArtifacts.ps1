function Find-MshRunnerArtifacts {
    <#
    .SYNOPSIS
        Mini Shai-Hulud check 9 — GitHub Actions self-hosted runner artifacts
        on a developer workstation.
    .DESCRIPTION
        If a dev box doubles as a self-hosted runner, it is the actual blast
        radius for stolen tokens — the worm primarily exfiltrates from CI
        runners. The presence of any of the standard runner directories is
        treated as Critical: we cannot tell from the file system alone whether
        the runner has been used during the attack window, but the existence
        of the runner artifact on a workstation justifies an immediate
        operational review.
    #>
    [CmdletBinding()]
    param()

    $findings = @()

    $candidates = @()
    $candidates += Join-Path $HOME 'actions-runner'
    $candidates += Join-Path $HOME '_work'
    $candidates += Join-Path $HOME '.runner'
    if ($IsWindows) {
        $candidates += 'C:\actions-runner'
        $candidates += 'C:\agent'
    } else {
        $candidates += '/opt/actions-runner'
        $candidates += '/srv/actions-runner'
    }

    # Discover additional candidates: any directory under HOME or /opt named exactly 'actions-runner'
    foreach ($root in @($HOME, '/opt')) {
        if (-not $root -or -not (Test-Path $root)) { continue }
        try {
            $more = Get-ChildItem -Path $root -Recurse -Depth 2 -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'actions-runner' -or $_.Name -eq '.runner' }
            foreach ($d in $more) { $candidates += $d.FullName }
        } catch { }
    }

    $seen = @{}
    foreach ($p in $candidates) {
        if (-not $p) { continue }
        if ($seen.ContainsKey($p)) { continue }
        $seen[$p] = $true
        if (-not (Test-Path $p)) { continue }

        try {
            $item = Get-Item $p -ErrorAction Stop
            $findings += New-Finding `
                -Type 'RunnerArtifact' `
                -Severity 'Critical' `
                -Description "GitHub Actions self-hosted runner artifact present at $p. A dev workstation doubling as a runner is a high-blast-radius target for Mini Shai-Hulud token theft. Treat the machine as runner infrastructure and rotate any tokens it has handled." `
                -Path $p `
                -Extra @{
                    LastWriteTime = $item.LastWriteTime
                    IsDirectory   = $item.PSIsContainer
                }
        } catch { }
    }

    return ,$findings
}
