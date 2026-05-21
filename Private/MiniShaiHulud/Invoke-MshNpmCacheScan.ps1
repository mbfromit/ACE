function Invoke-MshNpmCacheScan {
    <#
    .SYNOPSIS
        Mini Shai-Hulud check 7 — npm content-addressable cache hits on IOC packages.
    .DESCRIPTION
        Walks the npm cache (~/.npm/_cacache) and global node_modules looking
        for tarballs / package directories whose name matches any IOC entry.
        Cache hits prove the package was pulled at some point, even if the
        project that pulled it has since been cleaned.
        Remediation in the runbook: 'npm cache clean --force' and reinstall.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Iocs,
        [string]$CacheRootOverride
    )

    $findings = @()

    $cacheRoot = if ($CacheRootOverride) { $CacheRootOverride } else { Join-Path $HOME '.npm/_cacache' }
    if (Test-Path $cacheRoot) {
        $indexDir = Join-Path $cacheRoot 'index-v5'
        if (Test-Path $indexDir) {
            try {
                $entries = Get-ChildItem -Path $indexDir -Recurse -File -ErrorAction SilentlyContinue
                foreach ($e in $entries) {
                    try {
                        # Each index file is a stream of JSON lines (the cacache format).
                        $lines = Get-Content $e.FullName -ErrorAction Stop
                        foreach ($line in $lines) {
                            $jsonStart = $line.IndexOf('{')
                            if ($jsonStart -lt 0) { continue }
                            $jsonText = $line.Substring($jsonStart)
                            try { $entry = $jsonText | ConvertFrom-Json -ErrorAction Stop } catch { continue }
                            if (-not $entry.key) { continue }
                            # Keys look like: pacote:version-manifest:https://registry.npmjs.org/@scope/name/-/name-1.2.3.tgz
                            # or:             make-fetch-happen:request-cache:https://registry.npmjs.org/@scope/name
                            if ($entry.key -match '/([\w@/.-]+)/-/[\w.-]+-(\d[\w.+\-]*)\.tgz') {
                                $name = $matches[1]
                                $ver  = $matches[2]
                                if (Test-MshPackageMatch -Iocs $Iocs -Name $name -Version $ver) {
                                    $findings += New-Finding `
                                        -Type 'NpmCacheHit' `
                                        -Severity 'High' `
                                        -Description "Mini Shai-Hulud package $name@$ver cached in npm content-addressable store. Run 'npm cache clean --force' as part of remediation." `
                                        -Path $e.FullName `
                                        -Extra @{ PackageName = $name; Version = $ver; CacheKey = $entry.key }
                                }
                            }
                        }
                    } catch { }
                }
            } catch { }
        }
    }

    # Global npm — check `npm root -g`
    $globalRoot = $null
    try { $globalRoot = (& npm root -g 2>$null | Select-Object -First 1) } catch { }
    if ($globalRoot -and (Test-Path $globalRoot)) {
        try {
            $tops = Get-ChildItem -Path $globalRoot -Directory -ErrorAction SilentlyContinue
            $allPkgs = @()
            foreach ($t in $tops) {
                if ($t.Name.StartsWith('@')) {
                    $allPkgs += Get-ChildItem -Path $t.FullName -Directory -ErrorAction SilentlyContinue |
                        ForEach-Object { [PSCustomObject]@{ Path = $_.FullName; Name = "$($t.Name)/$($_.Name)" } }
                } else {
                    $allPkgs += [PSCustomObject]@{ Path = $t.FullName; Name = $t.Name }
                }
            }
            foreach ($p in $allPkgs) {
                $candPkg = Join-Path $p.Path 'package.json'
                if (-not (Test-Path $candPkg)) { continue }
                try {
                    $manifest = Get-Content $candPkg -Raw | ConvertFrom-Json -ErrorAction Stop
                    $name = if ($manifest.PSObject.Properties.Name -contains 'name') { [string]$manifest.name } else { $p.Name }
                    $ver  = if ($manifest.PSObject.Properties.Name -contains 'version') { [string]$manifest.version } else { '' }
                    if (Test-MshPackageMatch -Iocs $Iocs -Name $name -Version $ver) {
                        $findings += New-Finding `
                            -Type 'GlobalNpmHit' `
                            -Severity 'Critical' `
                            -Description "Mini Shai-Hulud package $name@$ver installed globally at $($p.Path). Uninstall with 'npm uninstall -g $name' and audit." `
                            -Path $p.Path `
                            -Extra @{ PackageName = $name; Version = $ver }
                    }
                } catch { }
            }
        } catch { }
    }

    return ,$findings
}
