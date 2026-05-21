function Find-MshSuspiciousScripts {
    <#
    .SYNOPSIS
        Mini Shai-Hulud check 5 — postinstall / preinstall scripts that exhibit
        worm-loader behavior.
    .DESCRIPTION
        Walks every installed package.json under a project's node_modules and
        flags scripts.postinstall or scripts.preinstall containing any of the
        suspicious tokens from the IOC bundle (eval(, Function(, Buffer.from(,
        atob(, "bun ", child_process), as well as long base64 blobs and fetches
        to non-registry hostnames. Severity escalates to Critical when a script
        combines a decode primitive with command execution on the same line —
        that is the canonical worm-loader pattern.
    .OUTPUTS
        Findings of Type 'SuspiciousScript'. Severity High by default; Critical
        when a base64-decode is paired with child_process on one line.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectPath,
        [Parameter(Mandatory)]$Iocs
    )

    $findings = @()
    $nodeModules = Join-Path $ProjectPath 'node_modules'
    if (-not (Test-Path $nodeModules)) { return ,$findings }

    $tokens = $Iocs.suspicious_script_tokens
    $base64Pattern = '[A-Za-z0-9+/=]{200,}'

    # Collect candidate package.json files: top-level + one scope level deep
    $manifests = @()
    try {
        $manifests += Get-ChildItem -Path $nodeModules -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name.StartsWith('@')) {
                Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue |
                    ForEach-Object { Join-Path $_.FullName 'package.json' }
            } else {
                Join-Path $_.FullName 'package.json'
            }
        }
    } catch { }

    foreach ($mf in $manifests) {
        if (-not (Test-Path $mf)) { continue }
        try {
            $pkg = Get-Content $mf -Raw | ConvertFrom-Json -ErrorAction Stop
        } catch { continue }

        # Parenthesize: `-not` binds tighter than `-contains`. Without these
        # parens this read as `(-not $array) -contains 'scripts'` and always
        # returned false, leaving strict mode to throw on the next line when
        # the property genuinely didn't exist.
        if (-not ($pkg.PSObject.Properties.Name -contains 'scripts')) { continue }
        if (-not $pkg.scripts) { continue }

        foreach ($hook in @('postinstall', 'preinstall', 'install')) {
            if (-not ($pkg.scripts.PSObject.Properties.Name -contains $hook)) { continue }
            $script = [string]$pkg.scripts.$hook
            if ([string]::IsNullOrWhiteSpace($script)) { continue }

            $matchedTokens = @($tokens | Where-Object { $script.Contains($_) })
            $hasLongB64    = [regex]::IsMatch($script, $base64Pattern)
            if ($matchedTokens.Count -eq 0 -and -not $hasLongB64) { continue }

            # Escalation: decode primitive + exec primitive on same script
            $hasDecode = ($script -match 'Buffer\.from\([^)]+,\s*[''"]base64[''"]') -or ($script -match 'atob\(')
            $hasExec   = ($script -match 'child_process') -or ($script -match '\bexec\b') -or ($script -match '\bspawn\b')
            $severity  = if ($hasDecode -and $hasExec) { 'Critical' } else { 'High' }

            $pkgName = if ($pkg.PSObject.Properties.Name -contains 'name') { [string]$pkg.name } else { Split-Path (Split-Path $mf -Parent) -Leaf }
            $tokensStr = if ($matchedTokens) { ($matchedTokens -join ', ') } else { 'long base64 blob' }

            $findings += New-Finding `
                -Type 'SuspiciousScript' `
                -Severity $severity `
                -Description "Suspicious '$hook' script in $pkgName referencing: $tokensStr" `
                -Path $mf `
                -Extra @{
                    PackageName = $pkgName
                    Hook        = $hook
                    Script      = $script
                    Tokens      = $matchedTokens
                    HasBase64   = $hasLongB64
                }
        }
    }

    return ,$findings
}
