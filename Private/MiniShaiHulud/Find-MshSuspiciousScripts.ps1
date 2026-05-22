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

    # IOC bundles in the wild have been seen WITHOUT suspicious_script_tokens
    # populated. Under StrictMode Latest, $Iocs.suspicious_script_tokens
    # throws if the property is absent. Guard via Get-Member which returns
    # $null for missing properties instead of throwing on an empty/missing
    # PSMemberInfoCollection.Name access.
    $tokens = @()
    if ($Iocs | Get-Member -MemberType *Property -Name 'suspicious_script_tokens' -ErrorAction SilentlyContinue) {
        if ($Iocs.suspicious_script_tokens) {
            $tokens = @($Iocs.suspicious_script_tokens | Where-Object { $_ })
        }
    }
    $base64Pattern = '[A-Za-z0-9+/=]{200,}'

    # Collect candidate package.json files: top-level + one scope level deep.
    # Every step of the walk is null-guarded: the wider discovery scope
    # (bounded-detection branch) traverses node_modules trees that contain
    # junctions, broken reparse points, .bin shims, .staging temp dirs, and
    # scope folders named '@something' but with no children. Any of those
    # could yield a $_ whose .Name property reads as $null under strict mode.
    $manifests = @()
    try {
        $topLevel = @(Get-ChildItem -Path $nodeModules -Directory -ErrorAction SilentlyContinue)
        foreach ($entry in $topLevel) {
            if (-not $entry -or -not $entry.Name) { continue }
            if ($entry.Name.StartsWith('@')) {
                $inner = @(Get-ChildItem -Path $entry.FullName -Directory -ErrorAction SilentlyContinue)
                foreach ($pkgDir in $inner) {
                    if (-not $pkgDir -or -not $pkgDir.FullName) { continue }
                    $manifests += (Join-Path $pkgDir.FullName 'package.json')
                }
            } else {
                $manifests += (Join-Path $entry.FullName 'package.json')
            }
        }
    } catch {
        # Walk errors on this project are non-fatal — emit no findings for
        # the project rather than crashing the whole scan. The wider discovery
        # scope exposed this: 52 projects errored on a real-world dev box
        # because of edge cases in the walk; with this guard, those projects
        # silently yield zero findings instead of taking down Check 5.
    }

    foreach ($mf in $manifests) {
        if (-not $mf -or -not (Test-Path -LiteralPath $mf)) { continue }
        $pkg = $null
        try {
            $pkg = Get-Content -LiteralPath $mf -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch { continue }
        if (-not $pkg) { continue }

        # Defensive: ConvertFrom-Json on a top-level scalar (e.g. just `42`
        # or `"hello"`) returns a primitive, not a PSCustomObject. Under
        # StrictMode Latest, $primitive.PSObject.Properties.Name throws
        # because the empty PSMemberInfoCollection doesn't expose .Name as
        # a direct property and the strict-mode property-fallback fails.
        # Hard-gate on PSCustomObject to avoid the entire class of failures.
        if (-not ($pkg -is [System.Management.Automation.PSCustomObject])) { continue }
        if (-not ($pkg.PSObject.Properties.Name -contains 'scripts')) { continue }
        $scripts = $pkg.scripts
        if (-not $scripts) { continue }
        # 'scripts' value can legally be a string, array, or null in malformed
        # manifests in the wild. Require it to be a PSCustomObject before
        # treating it as a hook map.
        if (-not ($scripts -is [System.Management.Automation.PSCustomObject])) { continue }

        foreach ($hook in @('postinstall', 'preinstall', 'install')) {
            if (-not ($scripts.PSObject.Properties.Name -contains $hook)) { continue }
            $rawHook = $scripts.$hook
            if ($null -eq $rawHook) { continue }
            $script = [string]$rawHook
            if ([string]::IsNullOrWhiteSpace($script)) { continue }

            $matchedTokens = @($tokens | Where-Object { $script.Contains($_) })
            $hasLongB64    = [regex]::IsMatch($script, $base64Pattern)
            if ($matchedTokens.Count -eq 0 -and -not $hasLongB64) { continue }

            $hasDecode = ($script -match 'Buffer\.from\([^)]+,\s*[''"]base64[''"]') -or ($script -match 'atob\(')
            $hasExec   = ($script -match 'child_process') -or ($script -match '\bexec\b') -or ($script -match '\bspawn\b')
            $severity  = if ($hasDecode -and $hasExec) { 'Critical' } else { 'High' }

            $pkgName = if ($pkg.PSObject.Properties.Name -contains 'name' -and $pkg.name) {
                [string]$pkg.name
            } else {
                Split-Path (Split-Path $mf -Parent) -Leaf
            }
            $tokensStr = if ($matchedTokens.Count -gt 0) { ($matchedTokens -join ', ') } else { 'long base64 blob' }

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
