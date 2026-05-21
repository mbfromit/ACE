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

Describe 'Get-MshIocs — schema v2 fields round-trip' {

    It 'bundled JSON exposes all v2 Tier-1 fields with defaults' {
        Mock Invoke-WebRequest { throw 'force fallback to bundled' }
        $iocs = Get-MshIocs -BundledPath $script:bundled -CachePath (Join-Path ([IO.Path]::GetTempPath()) "rc-test-$(New-Guid).json")

        $iocs.version | Should -BeGreaterOrEqual 2
        @($iocs.payload_filenames)     | Should -Contain 'bundle.js'
        @($iocs.workflow_filenames)    | Should -Contain 'shai-hulud-workflow.yml'
        @($iocs.dropper_filenames)     | Should -Contain 'processor.sh'
        @($iocs.dropper_drop_paths)    | Should -Contain '<node_project>'
        @($iocs.trufflehog_drop_paths) | Should -Contain '/tmp/trufflehog'
        @($iocs.exfil_repo_names)      | Should -Contain 'Shai-Hulud'
        @($iocs.exfil_repo_files)      | Should -Contain 'data.json'
        $iocs.payload_hashes           | Should -Not -BeNullOrEmpty
    }

    It 'hardcoded fallback exposes the same Tier-1 fields (offline parity)' {
        Mock Invoke-WebRequest { throw 'network down' }
        $iocs = Get-MshIocs -BundledPath '/no/such/file.json' -CachePath '/no/such/cache.json'
        $iocs.source | Should -Be 'fallback-hardcoded'

        @($iocs.payload_filenames)     | Should -Contain 'bundle.js'
        @($iocs.workflow_filenames)    | Should -Contain 'shai-hulud-workflow.yml'
        @($iocs.dropper_filenames)     | Should -Contain 'processor.sh'
        @($iocs.trufflehog_drop_paths) | Should -Contain '/tmp/trufflehog'
        @($iocs.exfil_repo_names)      | Should -Contain 'Shai-Hulud'
    }

    It 'old v1 feeds (no Tier-1 fields) still load and validate' {
        # Back-compat: a network endpoint serving the pre-v2 schema must still
        # work. The scanner's helpers handle absent fields by falling back to
        # built-in defaults (commit #3) — this confirms Get-MshIocs doesn't
        # reject the older shape.
        Mock Invoke-WebRequest {
            [PSCustomObject]@{
                Content = '{"version":1,"packages":[{"name":"mbt","versions":["1.2.48"]}],"campaign":"mini-shai-hulud","updated_at":"2026-04-01T00:00:00Z"}'
            }
        }
        $iocs = Get-MshIocs -CachePath (Join-Path ([IO.Path]::GetTempPath()) "rc-test-$(New-Guid).json")
        $iocs.source | Should -Be 'network'
        $iocs.PSObject.Properties['payload_filenames']  | Should -BeNullOrEmpty
        $iocs.PSObject.Properties['workflow_filenames'] | Should -BeNullOrEmpty
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
