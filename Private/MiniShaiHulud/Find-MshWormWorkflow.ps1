function Find-MshWormWorkflow {
    <#
    .SYNOPSIS
        Mini Shai-Hulud Check 13 — worm CI-persistence workflow file (Tier-1 IOC).
    .DESCRIPTION
        The Shai-Hulud worm writes a GitHub Actions workflow file into the
        compromised host's local repo clones, named `shai-hulud-workflow.yml`
        (variants: `shai-hulud.yml`, `shai-hulud.yaml`). This is the worm's
        own artifact — no legitimate code writes it. A single match is
        sufficient to declare CONFIRMED COMPROMISE.

        Probes `<repo>/.github/workflows/<name>` for each name in the IOC
        feed's `workflow_filenames` list. Constant-time per probe, no walks.

    .PARAMETER GitRoot
        Absolute path to a git repo (a directory where `.git` exists).
    .PARAMETER Iocs
        IOC bundle. Reads `workflow_filenames`; defaults to a sensible list
        if absent (back-compat with older feeds).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GitRoot,
        [Parameter(Mandatory)]$Iocs
    )

    $findings = @()

    $names = @($Iocs.PSObject.Properties['workflow_filenames']) |
             ForEach-Object { $_.Value } |
             Where-Object { $_ }
    if (-not $names -or $names.Count -eq 0) {
        $names = @('shai-hulud-workflow.yml', 'shai-hulud.yml', 'shai-hulud.yaml')
    }

    $wfDir = Join-Path (Join-Path $GitRoot '.github') 'workflows'
    if (-not (Test-Path -LiteralPath $wfDir)) { return $findings }

    foreach ($n in $names) {
        $candidate = Join-Path $wfDir $n
        if (-not (Test-Path -LiteralPath $candidate)) { continue }

        $excerpt = $null
        try {
            $bytes = [System.IO.File]::ReadAllBytes($candidate)
            $cap   = [Math]::Min($bytes.Length, 2048)
            $excerpt = [System.Text.Encoding]::UTF8.GetString($bytes, 0, $cap)
        } catch { }

        $fi = Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue

        $findings += New-Finding `
            -Type 'WormWorkflowFile' `
            -Severity 'Critical' `
            -Description ("Mini Shai-Hulud worm CI-persistence file present at $candidate — " +
                          "no legitimate code writes this filename. Confirmed compromise.") `
            -Path $candidate `
            -Extra @{
                RepoRoot      = $GitRoot
                Filename      = $n
                SizeBytes     = if ($fi) { $fi.Length } else { $null }
                LastWriteTime = if ($fi) { $fi.LastWriteTime } else { $null }
                Excerpt       = $excerpt
            }
    }

    return $findings
}
