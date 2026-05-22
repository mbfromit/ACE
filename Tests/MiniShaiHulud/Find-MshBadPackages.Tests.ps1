#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private/Shared/New-Finding.ps1')
    . (Join-Path $repoRoot 'Private/Shared/Get-LockfileText.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Get-MshIocs.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Invoke-MshNpmAudit.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Find-MshBadPackages.ps1')

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

Describe 'Find-MshBadPackages — legacy match-detection still works' {

    BeforeEach {
        $script:proj = Join-Path ([IO.Path]::GetTempPath()) "msh-test-$(New-Guid)"
        New-Item -Path $script:proj -ItemType Directory -Force | Out-Null
        # Every test in this Describe block runs with npm disabled so the
        # CLI is never invoked. Verdicts route through the npm-not-installed
        # branch, but match-detection itself is unaffected.
        Mock Test-MshNpmAvailable  { return $null }
        Mock Invoke-MshNpmAuditCli { throw 'should not be called' }
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

Describe 'Find-MshBadPackages — verdict envelope on emitted findings' {

    BeforeEach {
        $script:proj = Join-Path ([IO.Path]::GetTempPath()) "msh-verdict-$(New-Guid)"
        New-Item -Path $script:proj -ItemType Directory -Force | Out-Null
    }
    AfterEach {
        if (Test-Path $script:proj) { Remove-Item $script:proj -Recurse -Force -ErrorAction SilentlyContinue }
    }

    Context 'wildcard match + audit-clean (the @tanstack false-positive fix)' {

        It 'emits ScannerVerdict=Cleared, MatchedViaWildcard=true, no ActionRequired' {
            Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "@tanstack/react-query":"5.0.0" } }' -Encoding utf8
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/@tanstack/react-query": { "version":"5.0.0" } } }' -Encoding utf8
            Mock Test-MshNpmAvailable { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{
                    ExitCode = 0
                    StdOut   = '{"auditReportVersion":2,"vulnerabilities":{}}'
                    StdErr   = ''; TimedOut = $false; DurationMs = 10; Exception = $null
                }
            }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $r.Count | Should -BeGreaterThan 0
            foreach ($f in $r) {
                $f.MatchedViaWildcard | Should -Be $true
                $f.ScannerVerdict     | Should -Be 'Cleared'
                $f.AuditResult        | Should -Be 'audit-clean'
                $f.ActionRequired     | Should -BeNullOrEmpty
            }
        }
    }

    Context 'wildcard match + audit-flagged' {

        It 'emits ScannerVerdict=Confirmed with ActionRequired pointing at the runbook' {
            Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "@tanstack/react-query":"5.0.0" } }' -Encoding utf8
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/@tanstack/react-query": { "version":"5.0.0" } } }' -Encoding utf8
            $auditJson = '{"auditReportVersion":2,"vulnerabilities":{"@tanstack/react-query":{"name":"@tanstack/react-query","severity":"critical","via":[{"name":"@tanstack/react-query","title":"Malicious code","url":"https://example.test/a","severity":"critical"}]}}}'
            Mock Test-MshNpmAvailable { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{
                    ExitCode = 1; StdOut = $auditJson; StdErr = ''
                    TimedOut = $false; DurationMs = 10; Exception = $null
                }
            }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Where-Object { $_.PackageName -eq '@tanstack/react-query' } | Select-Object -First 1
            $f                       | Should -Not -BeNullOrEmpty
            $f.ScannerVerdict        | Should -Be 'Confirmed'
            $f.AuditResult           | Should -Be 'audit-flagged'
            $f.ActionRequired        | Should -Match 'incident response'
            $f.ActionTarget          | Should -Be 'UserAndManager'
            @($f.NpmAdvisories).Count | Should -BeGreaterThan 0
        }
    }

    Context 'exact-pinned match + audit-flagged' {

        It 'emits Confirmed (same path as wildcard+flagged, but MatchedViaWildcard=false)' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
            $auditJson = '{"auditReportVersion":2,"vulnerabilities":{"mbt":{"name":"mbt","severity":"critical","via":[{"name":"mbt","title":"shai-hulud payload","url":"https://example.test/m","severity":"critical"}]}}}'
            Mock Test-MshNpmAvailable { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{
                    ExitCode = 1; StdOut = $auditJson; StdErr = ''
                    TimedOut = $false; DurationMs = 10; Exception = $null
                }
            }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Select-Object -First 1
            $f.ScannerVerdict      | Should -Be 'Confirmed'
            $f.MatchedViaWildcard  | Should -Be $false
            $f.ActionRequired      | Should -Match 'incident response'
        }
    }

    Context 'exact-pinned match + audit-clean (feeds disagree)' {

        It 'emits Inconclusive citing the contradiction, no ActionRequired' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
            Mock Test-MshNpmAvailable { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{
                    ExitCode = 0
                    StdOut   = '{"auditReportVersion":2,"vulnerabilities":{}}'
                    StdErr   = ''; TimedOut = $false; DurationMs = 10; Exception = $null
                }
            }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Select-Object -First 1
            $f.ScannerVerdict        | Should -Be 'Inconclusive'
            $f.ScannerVerdictReason  | Should -Match 'disagree'
            $f.ActionRequired        | Should -BeNullOrEmpty
        }
    }

    Context 'npm not installed' {

        It 'wildcard + lockfile mtime before attack window → Cleared (no action)' {
            # Force lockfile mtime well before the IOC attack_window_start.
            Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "@tanstack/react-query":"5.0.0" } }' -Encoding utf8
            $lockPath = Join-Path $script:proj 'package-lock.json'
            Set-Content -Path $lockPath -Value '{ "lockfileVersion":3, "packages": { "node_modules/@tanstack/react-query": { "version":"5.0.0" } } }' -Encoding utf8
            (Get-Item $lockPath).LastWriteTimeUtc = [datetime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
            Mock Test-MshNpmAvailable  { return $null }
            Mock Invoke-MshNpmAuditCli { throw 'should not be called' }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Where-Object { $_.PackageName -eq '@tanstack/react-query' } | Select-Object -First 1
            $f.ScannerVerdict             | Should -Be 'Cleared'
            $f.LockfileBeforeAttackWindow | Should -Be $true
            $f.ActionRequired             | Should -BeNullOrEmpty
        }

        It 'wildcard + lockfile mtime inside attack window → Inconclusive + install instruction' {
            Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "@tanstack/react-query":"5.0.0" } }' -Encoding utf8
            $lockPath = Join-Path $script:proj 'package-lock.json'
            Set-Content -Path $lockPath -Value '{ "lockfileVersion":3, "packages": { "node_modules/@tanstack/react-query": { "version":"5.0.0" } } }' -Encoding utf8
            (Get-Item $lockPath).LastWriteTimeUtc = [datetime]::Parse('2026-05-15T00:00:00Z').ToUniversalTime()
            Mock Test-MshNpmAvailable  { return $null }
            Mock Invoke-MshNpmAuditCli { throw 'should not be called' }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Where-Object { $_.PackageName -eq '@tanstack/react-query' } | Select-Object -First 1
            $f.ScannerVerdict             | Should -Be 'Inconclusive'
            $f.LockfileBeforeAttackWindow | Should -Be $false
            $f.ActionRequired             | Should -Match 'nodejs\.org'
            $f.ActionTarget               | Should -Be 'User'
        }

        It 'exact-pin always Inconclusive regardless of mtime — install instruction set' {
            $lockPath = Join-Path $script:proj 'package-lock.json'
            Set-Content -Path $lockPath -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
            (Get-Item $lockPath).LastWriteTimeUtc = [datetime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
            Mock Test-MshNpmAvailable  { return $null }
            Mock Invoke-MshNpmAuditCli { throw 'should not be called' }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Select-Object -First 1
            $f.ScannerVerdict | Should -Be 'Inconclusive'
            $f.ActionRequired | Should -Match 'nodejs\.org'
        }
    }

    Context 'no-lockfile / corrupted-lockfile / network-error' {

        It 'routes manifest-only match (no lockfile) through no-lockfile when audit attempted' {
            Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "mbt":"1.2.48" } }' -Encoding utf8
            Mock Test-MshNpmAvailable  { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{
                    ExitCode = 1; StdOut = ''
                    StdErr   = 'npm ERR! code EUSAGE`nnpm ERR! `npm audit` requires existing shrinkwrap file or lockfile.'
                    TimedOut = $false; DurationMs = 10; Exception = $null
                }
            }
            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Select-Object -First 1
            $f.ScannerVerdict | Should -Be 'Inconclusive'
            $f.AuditResult    | Should -Be 'no-lockfile'
            $f.ActionRequired | Should -Match 'npm install'
        }

        It 'routes through corrupted-lockfile correctly' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
            Mock Test-MshNpmAvailable  { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{
                    ExitCode = 1; StdOut = ''
                    StdErr   = 'npm ERR! code EJSONPARSE`nnpm ERR! JSON.parse Failed to parse JSON'
                    TimedOut = $false; DurationMs = 10; Exception = $null
                }
            }
            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Select-Object -First 1
            $f.AuditResult    | Should -Be 'corrupted-lockfile'
            $f.ActionRequired | Should -Match 'corrupted'
        }

        It 'routes through network-error correctly' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
            Mock Test-MshNpmAvailable  { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{
                    ExitCode = 1; StdOut = ''; StdErr = 'npm ERR! code ENOTFOUND ...'
                    TimedOut = $false; DurationMs = 10; Exception = $null
                }
            }
            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Select-Object -First 1
            $f.AuditResult    | Should -Be 'network-error'
            $f.ActionRequired | Should -Match 'registry'
        }
    }

    Context '-SkipNpmAudit operator flag' {

        It 'skips the CLI entirely; verdicts route through not-applicable → Inconclusive' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
            Mock Test-MshNpmAvailable  { throw 'should not be called' }
            Mock Invoke-MshNpmAuditCli { throw 'should not be called' }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs -SkipNpmAudit)
            $f = $r | Select-Object -First 1
            $f.AuditResult        | Should -Be 'not-applicable'
            $f.ScannerVerdict     | Should -Be 'Inconclusive'
            Should -Invoke Test-MshNpmAvailable  -Times 0
            Should -Invoke Invoke-MshNpmAuditCli -Times 0
        }
    }

    Context 'severity + description reflect post-triage confidence (commit #3)' {

        It 'wildcard + audit-clean → severity High, description does NOT say "known compromised"' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/@tanstack/react-query": { "version":"5.0.0" } } }' -Encoding utf8
            Mock Test-MshNpmAvailable { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{ ExitCode=0; StdOut='{"auditReportVersion":2,"vulnerabilities":{}}'; StdErr=''
                                   TimedOut=$false; DurationMs=10; Exception=$null }
            }
            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Where-Object { $_.PackageName -eq '@tanstack/react-query' } | Select-Object -First 1
            $f.Severity     | Should -Be 'High'
            $f.Description  | Should -Not -Match 'compromised'
            $f.Description  | Should -Match 'watchlist'
        }

        It 'wildcard + audit-flagged (Confirmed) → severity Critical, description says "compromised"' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/@tanstack/react-query": { "version":"5.0.0" } } }' -Encoding utf8
            $auditJson = '{"auditReportVersion":2,"vulnerabilities":{"@tanstack/react-query":{"name":"@tanstack/react-query","severity":"critical","via":[{"name":"@tanstack/react-query","title":"x","url":"https://e.test/a","severity":"critical"}]}}}'
            Mock Test-MshNpmAvailable { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{ ExitCode=1; StdOut=$auditJson; StdErr=''
                                   TimedOut=$false; DurationMs=10; Exception=$null }
            }
            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Where-Object { $_.PackageName -eq '@tanstack/react-query' } | Select-Object -First 1
            $f.Severity    | Should -Be 'Critical'
            $f.Description | Should -Match 'compromised'
        }

        It 'exact-pin always Critical regardless of audit outcome (preserves prior behavior)' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
            Mock Test-MshNpmAvailable { return '/fake/npm' }
            # audit-clean — feeds disagree — Inconclusive verdict, but severity stays Critical
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{ ExitCode=0; StdOut='{"auditReportVersion":2,"vulnerabilities":{}}'; StdErr=''
                                   TimedOut=$false; DurationMs=10; Exception=$null }
            }
            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Select-Object -First 1
            $f.Severity       | Should -Be 'Critical'
            $f.ScannerVerdict | Should -Be 'Inconclusive'
            $f.Description    | Should -Match 'compromised'
        }

        It 'wildcard + npm-not-installed (Inconclusive) → severity High' {
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/@tanstack/react-query": { "version":"5.0.0" } } }' -Encoding utf8
            $lockPath = Join-Path $script:proj 'package-lock.json'
            (Get-Item $lockPath).LastWriteTimeUtc = [datetime]::Parse('2026-05-15T00:00:00Z').ToUniversalTime()
            Mock Test-MshNpmAvailable  { return $null }
            Mock Invoke-MshNpmAuditCli { throw 'should not be called' }
            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $f = $r | Where-Object { $_.PackageName -eq '@tanstack/react-query' } | Select-Object -First 1
            $f.Severity       | Should -Be 'High'
            $f.ScannerVerdict | Should -Be 'Inconclusive'
        }
    }

    Context 'npm-audit cache: one call per unique package even with N findings' {

        It 'invokes Invoke-MshNpmAuditCli only once when the same package appears in multiple checks' {
            # Same package matched by both lockfile (check 2) and manifest (check 3) — 2 findings, 1 audit call.
            Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{ "dependencies": { "mbt":"1.2.48" } }' -Encoding utf8
            Set-Content -Path (Join-Path $script:proj 'package-lock.json') -Value '{ "lockfileVersion":3, "packages": { "node_modules/mbt": { "version":"1.2.48" } } }' -Encoding utf8
            Mock Test-MshNpmAvailable  { return '/fake/npm' }
            Mock Invoke-MshNpmAuditCli {
                [PSCustomObject]@{
                    ExitCode = 0
                    StdOut   = '{"auditReportVersion":2,"vulnerabilities":{}}'
                    StdErr   = ''; TimedOut = $false; DurationMs = 10; Exception = $null
                }
            }

            $r = @(Find-MshBadPackages -ProjectPath $script:proj -Iocs $script:iocs)
            $r.Count | Should -BeGreaterThan 1   # at least lockfile + manifest
            Should -Invoke Invoke-MshNpmAuditCli -Times 1 -Exactly
        }
    }
}
