#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private\Shared\New-Finding.ps1')
    . (Join-Path $repoRoot 'Private\Shared\Get-LockfileText.ps1')
    . (Join-Path $repoRoot 'Private\MiniShaiHulud\Get-MshIocs.ps1')
    . (Join-Path $repoRoot 'Private\MiniShaiHulud\Find-MshBadPackages.ps1')

    $script:iocs = [PSCustomObject]@{
        packages = @(
            [PSCustomObject]@{ name = 'mbt';         versions = @('1.2.48') }
            [PSCustomObject]@{ name = '@tanstack/*'; versions = @('*') }
        )
        suspicious_script_tokens = @()
        attack_window_start = '2026-04-01T00:00:00Z'
        attack_window_end   = $null
    }
}

Describe 'Find-MshBadPackages' {

    BeforeEach {
        $script:proj = Join-Path ([IO.Path]::GetTempPath()) "msh-test-$(New-Guid)"
        New-Item -Path $script:proj -ItemType Directory -Force | Out-Null
    }
    AfterEach {
        if (Test-Path $script:proj) { Remove-Item $script:proj -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns no findings for a clean project' {
        Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "name":"clean", "dependencies": { "react": "18.0.0" } }' -Encoding utf8
        Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/react": { "version":"18.0.0" } } }' -Encoding utf8
        $r = Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs
        $r.Count | Should -Be 0
    }

    It 'fires Check 2 on lockfile match of an exact-pinned IOC' {
        Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
        $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
        ($r | Where-Object { $_.Type -eq 'BadPackage-Lockfile' }).Count | Should -BeGreaterThan 0
    }

    It 'fires Check 3 on package.json manifest match' {
        Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "mbt":"1.2.48" } }' -Encoding utf8
        $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
        ($r | Where-Object { $_.Type -eq 'BadPackage-Manifest' }).Count | Should -BeGreaterThan 0
    }

    It 'fires Check 4 even when lockfile is clean but installed package matches' {
        Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "mbt":"^2.0.0" } }' -Encoding utf8
        Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"2.0.0" } } }' -Encoding utf8
        # Two Join-Paths — literal 'node_modules\mbt' becomes a single
        # filename on Unix because backslash isn't a separator there.
        $instDir = Join-Path (Join-Path $script:proj 'node_modules') 'mbt'
        New-Item -Path $instDir -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $instDir 'package.json') -Value '{ "name":"mbt","version":"1.2.48" }' -Encoding utf8
        $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
        ($r | Where-Object { $_.Type -eq 'BadPackage-Installed' }).Count | Should -BeGreaterThan 0
    }

    It 'matches scope wildcards (@tanstack/*) in package.json' {
        Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "@tanstack/react-query":"5.0.0" } }' -Encoding utf8
        $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
        ($r | Where-Object { $_.Type -eq 'BadPackage-Manifest' }).Count | Should -BeGreaterThan 0
    }
}
