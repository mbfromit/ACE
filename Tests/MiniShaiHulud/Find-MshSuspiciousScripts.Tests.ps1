#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private/Shared/New-Finding.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Find-MshSuspiciousScripts.ps1')

    # Pester 5: functions need to live in BeforeAll to be visible inside It
    # blocks. Defining at Describe level works at discovery time but the
    # symbol isn't in the It block's runtime scope.
    function _Plant {
        param([string]$name, [string]$content)
        $d = Join-Path $script:nm $name
        New-Item -Path $d -ItemType Directory -Force | Out-Null
        $content | Set-Content -LiteralPath (Join-Path $d 'package.json') -Encoding utf8
    }
}

Describe 'Find-MshSuspiciousScripts — StrictMode resilience to malformed package.json' {

    BeforeEach {
        # Enable StrictMode Latest in this It block scope to match what
        # Invoke-MiniShaiHulud sets at the top of the entry script. Without
        # this, the bug we're guarding against silently passes.
        Set-StrictMode -Version Latest
        $script:proj = Join-Path ([IO.Path]::GetTempPath()) "msh-ss-$(New-Guid)"
        $script:nm   = Join-Path $script:proj 'node_modules'
        New-Item -Path $script:nm -ItemType Directory -Force | Out-Null
        $script:iocs = [PSCustomObject]@{
            suspicious_script_tokens = @('eval(', 'Buffer.from(', 'atob(', 'child_process', 'bun ')
        }
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:proj) {
            Remove-Item -LiteralPath $script:proj -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not throw on a package.json that is a top-level JSON number' {
        # The real-world failure mode: a single project's malformed manifest
        # (anywhere in node_modules) used to kill the entire Check 5 pass
        # for that project. With the guard, it just gets skipped.
        _Plant 'number-top' '42'
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs } | Should -Not -Throw
    }

    It 'does not throw on a package.json that is a top-level JSON array' {
        _Plant 'arr-top' '[1,2,3]'
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs } | Should -Not -Throw
    }

    It 'does not throw when scripts value is a string instead of an object' {
        _Plant 'string-scripts' '{"name":"x","scripts":"build"}'
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs } | Should -Not -Throw
    }

    It 'does not throw when scripts value is an array instead of an object' {
        _Plant 'array-scripts' '{"name":"x","scripts":["a","b"]}'
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs } | Should -Not -Throw
    }

    It 'does not throw when scripts value is null' {
        _Plant 'null-scripts' '{"name":"x","scripts":null}'
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs } | Should -Not -Throw
    }

    It 'does not throw when an individual hook value is null' {
        _Plant 'hook-null' '{"name":"x","scripts":{"postinstall":null,"build":"webpack"}}'
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs } | Should -Not -Throw
    }

    It 'does not throw when package name is missing or null' {
        _Plant 'no-name'   '{"scripts":{"postinstall":"eval(decoded)"}}'
        _Plant 'null-name' '{"name":null,"scripts":{"postinstall":"atob(p)"}}'
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs } | Should -Not -Throw
    }

    It 'does not throw on empty scope folders or .bin / .staging directories' {
        New-Item -Path (Join-Path $script:nm '@emptyscope') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $script:nm '.bin') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $script:nm '.staging') -ItemType Directory -Force | Out-Null
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs } | Should -Not -Throw
    }

    It 'does not throw when IOC bundle has no suspicious_script_tokens field' {
        _Plant 'good' '{"name":"good","scripts":{"postinstall":"eval(decoded)"}}'
        $bareIocs = [PSCustomObject]@{ packages = @() }
        { Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $bareIocs } | Should -Not -Throw
    }

    It 'still emits findings for genuinely suspicious scripts (regression of the regression)' {
        # Plant via PSCustomObject -> JSON to avoid shell-quote hell. Want
        # the postinstall body to contain BOTH Buffer.from(..., "base64")
        # AND child_process so the decode+exec escalation triggers.
        $manifest = [PSCustomObject]@{
            name    = 'evil'
            scripts = [PSCustomObject]@{
                postinstall = 'node -e "var b=Buffer.from(blob, ''base64'');require(''child_process'').exec(b)"'
            }
        }
        $d = Join-Path $script:nm 'evil'
        New-Item -Path $d -ItemType Directory -Force | Out-Null
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $d 'package.json') -Encoding utf8

        $r = @(Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs)
        $r.Count | Should -BeGreaterThan 0
        $r[0].Severity | Should -Be 'Critical'   # decode + exec → escalation
    }

    It 'mixed: malformed entries skipped, good entries still flagged' {
        _Plant 'arr-top'       '[1,2,3]'
        _Plant 'string-scripts' '{"name":"strscr","scripts":"build"}'
        _Plant 'good-evil'      '{"name":"good-evil","scripts":{"postinstall":"eval(decoded)"}}'
        $r = @(Find-MshSuspiciousScripts -ProjectPath $script:proj -Iocs $script:iocs)
        $r.Count | Should -Be 1
        $r[0].PackageName | Should -Be 'good-evil'
    }
}
