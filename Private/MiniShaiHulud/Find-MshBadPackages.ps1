function Find-MshBadPackages {
    <#
    .SYNOPSIS
        Mini Shai-Hulud checks 2 / 3 / 4 — bad packages in lockfile, package.json,
        and physically installed under node_modules.
    .DESCRIPTION
        For one project, looks for any IOC name@version match across three
        sources, in this order:
            2. Lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml)
            3. package.json dependencies / devDependencies (catches lockfile drift)
            4. node_modules/<scope>/<name>/package.json on disk (catches anti-
               forensic lockfile cleanup — the worm has been observed rewriting
               lockfiles after install)
        Wildcard scopes from the IOC bundle (e.g. @tanstack/*) are honored.
    .OUTPUTS
        Findings with Type ∈ { 'BadPackage-Lockfile', 'BadPackage-Manifest',
        'BadPackage-Installed' }. All Critical.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectPath,
        [Parameter(Mandatory)]$Iocs
    )

    $findings = @()

    # ── Check 2: lockfile ─────────────────────────────────────────────────────
    $lock = Get-LockfileText -ProjectPath $ProjectPath
    if ($lock.Type -and $lock.Content) {
        $content = $lock.Content
        foreach ($p in $Iocs.packages) {
            $name = $p.name
            $isWildcard = $name.EndsWith('/*')
            $needle = if ($isWildcard) { $name.Substring(0, $name.Length - 2) } else { $name }
            $escaped = [regex]::Escape($needle)

            $regex = switch ($lock.Type) {
                'npm'  {
                    if ($isWildcard) {
                        # Match any package under the scope, capture name + version
                        "`"(?:node_modules/)?($escaped/[^`"]+)`"\s*:\s*\{[^`"]*`"version`"\s*:\s*`"([^`"]+)`""
                    } else {
                        "`"(?:node_modules/)?($escaped)`"\s*:\s*\{[^`"]*`"version`"\s*:\s*`"([^`"]+)`""
                    }
                }
                'yarn' {
                    if ($isWildcard) {
                        "(?m)^(?:`")?($escaped/[^@\n]+)@[^\n]+\n\s+version\s+`"([^`"]+)`""
                    } else {
                        "(?m)^(?:`")?($escaped)@[^\n]+\n\s+version\s+`"([^`"]+)`""
                    }
                }
                'pnpm' {
                    if ($isWildcard) {
                        "(?m)^\s+(?:/|)($escaped/[^/@\s:]+)[/@]([^\s:]+):"
                    } else {
                        "(?m)^\s+(?:/|)($escaped)[/@]([^\s:]+):"
                    }
                }
            }

            foreach ($m in [regex]::Matches($content, $regex)) {
                $matchedName = $m.Groups[1].Value
                $matchedVer  = $m.Groups[2].Value
                if (Test-MshPackageMatch -Iocs $Iocs -Name $matchedName -Version $matchedVer) {
                    $findings += New-Finding `
                        -Type 'BadPackage-Lockfile' `
                        -Severity 'Critical' `
                        -Description "Known Mini Shai-Hulud compromised package $matchedName@$matchedVer in $($lock.Type) lockfile" `
                        -Path $lock.Path `
                        -Extra @{
                            PackageName = $matchedName
                            Version     = $matchedVer
                            LockfileType = $lock.Type
                        }
                }
            }
        }
    }

    # ── Check 3: package.json direct dependencies ─────────────────────────────
    $pkgJsonPath = Join-Path $ProjectPath 'package.json'
    if (Test-Path $pkgJsonPath) {
        try {
            $pkg = Get-Content $pkgJsonPath -Raw | ConvertFrom-Json -ErrorAction Stop
            $deps = @{}
            foreach ($section in @('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')) {
                if ($pkg.PSObject.Properties.Name -contains $section -and $pkg.$section) {
                    foreach ($prop in $pkg.$section.PSObject.Properties) {
                        $deps[$prop.Name] = [string]$prop.Value
                    }
                }
            }
            foreach ($depName in $deps.Keys) {
                # Strip semver range characters to compare a concrete version where possible
                $rawVer = $deps[$depName]
                $cleanVer = $rawVer -replace '^[\^~>=<\s]+', ''
                if (Test-MshPackageMatch -Iocs $Iocs -Name $depName -Version $cleanVer) {
                    $findings += New-Finding `
                        -Type 'BadPackage-Manifest' `
                        -Severity 'Critical' `
                        -Description "Known Mini Shai-Hulud compromised package $depName@$rawVer pinned in package.json" `
                        -Path $pkgJsonPath `
                        -Extra @{ PackageName = $depName; Version = $rawVer }
                }
            }
        } catch {
            # Malformed package.json — skip; check 4 may still catch it on disk
        }
    }

    # ── Check 4: physical node_modules presence ───────────────────────────────
    $nodeModules = Join-Path $ProjectPath 'node_modules'
    if (Test-Path $nodeModules) {
        # Enumerate top-level package directories AND one level of @scope subdirs
        $candidates = @()
        try {
            $candidates += Get-ChildItem -Path $nodeModules -Directory -ErrorAction SilentlyContinue
        } catch { }
        $scopeDirs = $candidates | Where-Object { $_.Name.StartsWith('@') }
        foreach ($scope in $scopeDirs) {
            try {
                $candidates += Get-ChildItem -Path $scope.FullName -Directory -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        # Synthesize a record whose Name is "scope/pkg"
                        [PSCustomObject]@{ FullName = $_.FullName; Name = "$($scope.Name)/$($_.Name)" }
                    }
            } catch { }
        }

        foreach ($cand in $candidates) {
            # Skip the scope-only entries themselves
            if ($cand.Name.StartsWith('@') -and -not $cand.Name.Contains('/')) { continue }
            $candPkg = Join-Path $cand.FullName 'package.json'
            if (-not (Test-Path $candPkg)) { continue }
            try {
                $manifest = Get-Content $candPkg -Raw | ConvertFrom-Json -ErrorAction Stop
                $name = if ($manifest.PSObject.Properties.Name -contains 'name') { [string]$manifest.name } else { $cand.Name }
                $ver  = if ($manifest.PSObject.Properties.Name -contains 'version') { [string]$manifest.version } else { '' }
                if (Test-MshPackageMatch -Iocs $Iocs -Name $name -Version $ver) {
                    $findings += New-Finding `
                        -Type 'BadPackage-Installed' `
                        -Severity 'Critical' `
                        -Description "Known Mini Shai-Hulud compromised package $name@$ver physically installed in node_modules (lockfile may have been cleaned)" `
                        -Path $cand.FullName `
                        -Extra @{ PackageName = $name; Version = $ver }
                }
            } catch { }
        }
    }

    return ,$findings
}
