#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private\MiniShaiHulud\Get-MshIocs.ps1')

    $script:bundled = Join-Path $repoRoot 'Private\MiniShaiHulud\MiniShaiHulud-IOCs.json'
}

Describe 'Get-MshIocs — fallback chain' {

    It 'returns network bundle when the endpoint succeeds' {
        Mock Invoke-WebRequest {
            [PSCustomObject]@{
                Content = '{"version":1,"packages":[{"name":"mbt","versions":["1.2.48"]}],"campaign":"mini-shai-hulud","updated_at":"2026-05-01T00:00:00Z"}'
            }
        }
        $iocs = Get-MshIocs -CachePath (Join-Path ([IO.Path]::GetTempPath()) "rc-test-$(New-Guid).json")
        $iocs.source | Should -Be 'network'
        $iocs.packages.Count | Should -BeGreaterThan 0
    }

    It 'falls back to bundled when network fails' {
        Mock Invoke-WebRequest { throw 'network down' }
        $iocs = Get-MshIocs -BundledPath $script:bundled -CachePath (Join-Path ([IO.Path]::GetTempPath()) "rc-test-$(New-Guid).json")
        $iocs.source | Should -Be 'bundled'
        $iocs.packages.Count | Should -BeGreaterThan 0
    }

    It 'falls back to cache when network and bundled both fail' {
        $cache = Join-Path ([IO.Path]::GetTempPath()) "rc-test-$(New-Guid).json"
        '{"version":1,"packages":[{"name":"mbt","versions":["1.2.48"]}],"campaign":"mini-shai-hulud","updated_at":"2026-04-01T00:00:00Z"}' |
            Out-File -FilePath $cache -Encoding utf8
        Mock Invoke-WebRequest { throw 'network down' }
        $iocs = Get-MshIocs -BundledPath '/no/such/file.json' -CachePath $cache
        $iocs.source | Should -Be 'cache'
        Remove-Item $cache -Force -ErrorAction SilentlyContinue
    }

    It 'falls back to hardcoded when every other source fails' {
        Mock Invoke-WebRequest { throw 'network down' }
        $iocs = Get-MshIocs -BundledPath '/no/such/file.json' -CachePath '/no/such/cache.json'
        $iocs.source | Should -Be 'fallback-hardcoded'
        $iocs.packages.Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-MshPackageMatch — wildcard handling' {

    BeforeAll {
        $script:iocs = [PSCustomObject]@{
            packages = @(
                [PSCustomObject]@{ name = 'mbt';            versions = @('1.2.48') }
                [PSCustomObject]@{ name = '@tanstack/*';    versions = @('*') }
                [PSCustomObject]@{ name = '@cap-js/sqlite'; versions = @('2.2.2') }
            )
        }
    }

    It 'matches an exact name+version' {
        Test-MshPackageMatch -Iocs $script:iocs -Name 'mbt' -Version '1.2.48' | Should -BeTrue
    }
    It 'does not match a different version of an exact-pinned package' {
        Test-MshPackageMatch -Iocs $script:iocs -Name 'mbt' -Version '1.2.49' | Should -BeFalse
    }
    It 'matches any version under a scope wildcard' {
        Test-MshPackageMatch -Iocs $script:iocs -Name '@tanstack/react-query' -Version '5.0.0' | Should -BeTrue
        Test-MshPackageMatch -Iocs $script:iocs -Name '@tanstack/react-router' -Version '999.999.999' | Should -BeTrue
    }
    It 'does not match a package outside the IOC scope' {
        Test-MshPackageMatch -Iocs $script:iocs -Name 'react' -Version '18.0.0' | Should -BeFalse
        Test-MshPackageMatch -Iocs $script:iocs -Name '@notbad/foo' -Version '1.0' | Should -BeFalse
    }
}
