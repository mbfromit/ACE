#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private/Shared/Redact-Secrets.ps1')
    . (Join-Path $repoRoot 'Private/Shared/New-Finding.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Find-MshShellHistoryPublishes.ps1')
}

Describe 'Find-MshShellHistoryPublishes — secret redaction at finder boundary' {

    BeforeEach {
        # Sandbox dir used as the finder's HomePath override. $HOME itself
        # is a PowerShell constant and can't be reassigned, so the finder
        # was given a -HomePath parameter for testability.
        $script:sandboxHome = Join-Path ([IO.Path]::GetTempPath()) "msh-shp-$(New-Guid)"
        New-Item -Path $script:sandboxHome -ItemType Directory -Force | Out-Null

        # Mock PSReadline lookup so we don't accidentally pull in the
        # actual user's PS history. Returns a path that doesn't exist.
        Mock Get-PSReadLineOption {
            [PSCustomObject]@{ HistorySavePath = (Join-Path $script:sandboxHome 'no-such.history') }
        }

        $script:iocs = [PSCustomObject]@{
            attack_window_start = '2026-04-01T00:00:00Z'
            attack_window_end   = $null
        }
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:sandboxHome) {
            Remove-Item -LiteralPath $script:sandboxHome -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'strips NPM_TOKEN= value from a bash_history npm publish line' {
        $rawSecret = 'npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $line = "NPM_TOKEN=$rawSecret npm publish --access public"
        Set-Content -LiteralPath (Join-Path $script:sandboxHome '.bash_history') -Value $line -Encoding utf8

        $r = @(Find-MshShellHistoryPublishes -Iocs $script:iocs -HomePath $script:sandboxHome)
        $r.Count | Should -BeGreaterThan 0
        # The Command field is the field that captured the raw line.
        $r[0].Command           | Should -Not -Match 'npm_a{36}'
        $r[0].Command           | Should -Match '<REDACTED:'
        $r[0].RedactionApplied  | Should -Be $true
    }

    It 'strips --token CLI flag value from a publish line' {
        $rawSecret = 'npm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        $line = "npm publish --token=$rawSecret"
        Set-Content -LiteralPath (Join-Path $script:sandboxHome '.bash_history') -Value $line -Encoding utf8

        $r = @(Find-MshShellHistoryPublishes -Iocs $script:iocs -HomePath $script:sandboxHome)
        $r.Count | Should -BeGreaterThan 0
        $r[0].Command | Should -Not -Match $rawSecret
        $r[0].Command | Should -Match '<REDACTED:'
    }

    It 'strips a basic-auth URL embedded in a publish line, preserving host' {
        $line = 'npm publish https://alice:s3cret@registry.internal.example.com/'
        Set-Content -LiteralPath (Join-Path $script:sandboxHome '.bash_history') -Value $line -Encoding utf8

        $r = @(Find-MshShellHistoryPublishes -Iocs $script:iocs -HomePath $script:sandboxHome)
        $r.Count | Should -BeGreaterThan 0
        $r[0].Command | Should -Not -Match 's3cret'
        $r[0].Command | Should -Match 'registry\.internal\.example\.com'
        $r[0].Command | Should -Match '<REDACTED:basic-auth>'
    }

    It 'does NOT set RedactionApplied on a clean publish line (no secrets)' {
        $line = 'npm publish --access public'
        Set-Content -LiteralPath (Join-Path $script:sandboxHome '.bash_history') -Value $line -Encoding utf8

        $r = @(Find-MshShellHistoryPublishes -Iocs $script:iocs -HomePath $script:sandboxHome)
        $r.Count | Should -BeGreaterThan 0
        # RedactionApplied is set on Extra only when a pattern fires.
        # PowerShell PSCustomObject: missing property accessed under
        # StrictMode would throw, so check via PSObject.Properties.
        ($r[0].PSObject.Properties.Name -contains 'RedactionApplied') | Should -Be $false
    }

    It 'handles multi-line bash_history with mixed clean + secret-bearing lines' {
        $secret = 'ghp_cccccccccccccccccccccccccccccccccccc'
        $lines = @(
            'npm publish --access public'
            "GITHUB_TOKEN=$secret npm publish"
            'npm publish another-package'
        )
        Set-Content -LiteralPath (Join-Path $script:sandboxHome '.bash_history') -Value ($lines -join "`n") -Encoding utf8

        # The finder uses `return ,$findings` which collapses under @()
        # into a 1-element wrapper; pipe through ForEach-Object to flatten.
        $r = Find-MshShellHistoryPublishes -Iocs $script:iocs -HomePath $script:sandboxHome | ForEach-Object { $_ }
        @($r).Count | Should -BeGreaterOrEqual 3
        # No finding's Command may contain the raw secret.
        foreach ($f in @($r)) {
            $f.Command | Should -Not -Match 'ghp_c{36}'
        }
        # At least one finding should be flagged as redacted.
        @($r | Where-Object { $_.PSObject.Properties.Name -contains 'RedactionApplied' -and $_.RedactionApplied }).Count | Should -BeGreaterThan 0
    }
}
