#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Invoke-MshNpmAudit.ps1')
}

Describe 'Invoke-MshNpmAudit — input validation' {

    It "returns AuditResult='not-applicable' when PackageName is empty" {
        # Don't even need a real ProjectPath — the helper short-circuits
        # before touching the filesystem.
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\does\not\matter' -PackageName ''
        $r.AuditResult | Should -Be 'not-applicable'
        $r.Concurs     | Should -BeNullOrEmpty
        @($r.Advisories).Count | Should -Be 0
    }

    It "returns AuditResult='not-applicable' when PackageName is whitespace" {
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\nope' -PackageName "  `t  "
        $r.AuditResult | Should -Be 'not-applicable'
    }
}

Describe 'Invoke-MshNpmAudit — npm not installed' {

    It "returns 'npm-not-installed' and skips the CLI when npm is absent" {
        Mock Test-MshNpmAvailable { return $null }
        Mock Invoke-MshNpmAuditCli { throw 'CLI should not have been called' }

        $r = Invoke-MshNpmAudit -ProjectPath 'C:\anyproj' -PackageName '@tanstack/react-query'

        $r.AuditResult | Should -Be 'npm-not-installed'
        $r.Concurs     | Should -BeNullOrEmpty
        $r.ErrorDetail | Should -Match 'nodejs\.org'
        Should -Invoke Invoke-MshNpmAuditCli -Times 0
    }
}

Describe 'Invoke-MshNpmAudit — classifier' {

    BeforeEach {
        # All classifier tests use a fake npm path so the real PATH lookup
        # is irrelevant. The CLI mock provides the synthetic output each
        # test needs.
        Mock Test-MshNpmAvailable { return '/fake/npm' }
    }

    It "returns 'audit-clean' + Concurs=`$false when npm audit reports no vulns" {
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode   = 0
                StdOut     = '{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"total":0}}}'
                StdErr     = ''
                TimedOut   = $false
                DurationMs = 42
                Exception  = $null
            }
        }

        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'lodash' -PackageVersion '4.17.21'

        $r.AuditResult | Should -Be 'audit-clean'
        $r.Concurs     | Should -Be $false
        @($r.Advisories).Count | Should -Be 0
        $r.DurationMs  | Should -Be 42
    }

    It "returns 'audit-clean' when vulnerabilities exist but not for the queried package" {
        # npm audit exits 1 when ANY package is flagged, even if it isn't ours.
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = 1
                StdOut   = '{"auditReportVersion":2,"vulnerabilities":{"some-other-pkg":{"name":"some-other-pkg","severity":"low","via":[]}}}'
                StdErr   = ''
                TimedOut = $false; DurationMs = 10; Exception = $null
            }
        }

        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName '@tanstack/react-query' -PackageVersion '5.0.0'
        $r.AuditResult | Should -Be 'audit-clean'
        $r.Concurs     | Should -Be $false
    }

    It "returns 'audit-flagged' + populated Advisories when npm flags the queried package" {
        $auditJson = @'
{
  "auditReportVersion": 2,
  "vulnerabilities": {
    "mbt": {
      "name": "mbt",
      "severity": "critical",
      "via": [
        { "source": 99001, "name": "mbt", "dependency": "mbt", "title": "Malicious code in mbt 1.2.48", "url": "https://example.test/advisory/99001", "severity": "critical", "range": ">=1.2.48 <1.2.49" }
      ],
      "effects": [], "range": ">=1.2.48 <1.2.49", "nodes": ["node_modules/mbt"], "fixAvailable": false
    }
  }
}
'@
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = 1; StdOut = $auditJson; StdErr = ''
                TimedOut = $false; DurationMs = 88; Exception = $null
            }
        }

        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'mbt' -PackageVersion '1.2.48'

        $r.AuditResult | Should -Be 'audit-flagged'
        $r.Concurs     | Should -Be $true
        @($r.Advisories).Count | Should -Be 1
        $r.Advisories[0].Package  | Should -Be 'mbt'
        $r.Advisories[0].Severity | Should -Be 'critical'
        $r.Advisories[0].Url      | Should -Match 'advisory/99001'
        $r.Advisories[0].Title    | Should -Match 'Malicious code'
    }

    It "returns 'audit-flagged' with a stub advisory when the entry has no `via` records" {
        # Defensive case: npm advisory entry present but `via` is empty/string-only.
        $auditJson = '{"auditReportVersion":2,"vulnerabilities":{"mbt":{"name":"mbt","severity":"high","via":["transitive-only"]}}}'
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = 1; StdOut = $auditJson; StdErr = ''
                TimedOut = $false; DurationMs = 5; Exception = $null
            }
        }
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'mbt'
        $r.AuditResult | Should -Be 'audit-flagged'
        @($r.Advisories).Count | Should -Be 1
        $r.Advisories[0].Severity | Should -Be 'high'
    }

    It "returns 'network-error' when the CLI times out" {
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = -1; StdOut = ''; StdErr = ''
                TimedOut = $true; DurationMs = 30000; Exception = $null
            }
        }
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'lodash' -TimeoutSec 30
        $r.AuditResult | Should -Be 'network-error'
        $r.Concurs     | Should -BeNullOrEmpty
        $r.ErrorDetail | Should -Match '30s'
    }

    It "returns 'network-error' when stderr contains ENOTFOUND" {
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = 1; StdOut = ''
                StdErr   = 'npm ERR! code ENOTFOUND`nnpm ERR! errno ENOTFOUND`nnpm ERR! request to https://registry.npmjs.org/lodash failed, reason: getaddrinfo ENOTFOUND registry.npmjs.org'
                TimedOut = $false; DurationMs = 1200; Exception = $null
            }
        }
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'lodash'
        $r.AuditResult | Should -Be 'network-error'
        $r.Concurs     | Should -BeNullOrEmpty
    }

    It "returns 'no-lockfile' when stderr complains about missing package-lock.json" {
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = 1; StdOut = ''
                StdErr   = 'npm ERR! code EUSAGE`nnpm ERR! `npm audit` requires existing shrinkwrap file or lockfile.'
                TimedOut = $false; DurationMs = 50; Exception = $null
            }
        }
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'lodash'
        $r.AuditResult | Should -Be 'no-lockfile'
        $r.Concurs     | Should -BeNullOrEmpty
        $r.ErrorDetail | Should -Match 'npm install'
    }

    It "returns 'corrupted-lockfile' when stderr indicates JSON parse failure on the lockfile" {
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = 1; StdOut = ''
                StdErr   = 'npm ERR! code EJSONPARSE`nnpm ERR! JSON.parse Failed to parse JSON in package-lock.json'
                TimedOut = $false; DurationMs = 30; Exception = $null
            }
        }
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'lodash'
        $r.AuditResult | Should -Be 'corrupted-lockfile'
        $r.Concurs     | Should -BeNullOrEmpty
    }

    It "returns 'audit-failed' when the CLI emits no parseable JSON and no recognized error" {
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = 1; StdOut = 'not json at all'
                StdErr   = 'something weird happened'
                TimedOut = $false; DurationMs = 20; Exception = $null
            }
        }
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'lodash'
        $r.AuditResult | Should -Be 'audit-failed'
        $r.Concurs     | Should -BeNullOrEmpty
        $r.ErrorDetail | Should -Match 'weird'
    }

    It "returns 'audit-failed' when the process itself fails to start" {
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = -1; StdOut = ''; StdErr = ''
                TimedOut = $false; DurationMs = 0
                Exception = 'The system cannot find the file specified'
            }
        }
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'lodash'
        $r.AuditResult | Should -Be 'audit-failed'
        $r.ErrorDetail | Should -Match 'Failed to start npm'
    }
}

Describe 'Invoke-MshNpmAudit — DurationMs is preserved from the CLI' {

    It "passes DurationMs through to the result" {
        Mock Test-MshNpmAvailable  { return '/fake/npm' }
        Mock Invoke-MshNpmAuditCli {
            [PSCustomObject]@{
                ExitCode = 0
                StdOut   = '{"auditReportVersion":2,"vulnerabilities":{}}'
                StdErr   = ''; TimedOut = $false; DurationMs = 1234; Exception = $null
            }
        }
        $r = Invoke-MshNpmAudit -ProjectPath 'C:\proj' -PackageName 'x'
        $r.DurationMs | Should -Be 1234
    }
}
