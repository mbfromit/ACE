#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Find-MshDiscoveryRoots.ps1')
}

Describe 'Find-MshDiscoveryRoots' {

    BeforeEach {
        $script:sandbox = Join-Path ([IO.Path]::GetTempPath()) "msh-disc-$(New-Guid)"
        New-Item -Path $script:sandbox -ItemType Directory -Force | Out-Null
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:sandbox) {
            Remove-Item -LiteralPath $script:sandbox -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'marker detection' {

        It 'finds a Node project (package.json marker)' {
            $proj = Join-Path $script:sandbox 'myapp'
            New-Item -Path $proj -ItemType Directory -Force | Out-Null
            Set-Content -Path (Join-Path $proj 'package.json') -Value '{}' -Encoding utf8

            $r = Find-MshDiscoveryRoots -Path @($script:sandbox)
            $hit = @($r.Roots) | Where-Object { $_.Path -eq $proj }
            $hit.Count | Should -Be 1
            $hit[0].Type | Should -Be 'node_project'
        }

        It 'finds a git repo (.git directory marker)' {
            $repo = Join-Path $script:sandbox 'myrepo'
            New-Item -Path $repo -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path $repo '.git') -ItemType Directory -Force | Out-Null

            $r = Find-MshDiscoveryRoots -Path @($script:sandbox)
            $hit = @($r.Roots) | Where-Object { $_.Path -eq $repo }
            $hit.Count | Should -Be 1
            $hit[0].Type | Should -Be 'git_repo'
        }

        It 'finds a .git FILE marker (worktree pointer case)' {
            $repo = Join-Path $script:sandbox 'worktree'
            New-Item -Path $repo -ItemType Directory -Force | Out-Null
            Set-Content -Path (Join-Path $repo '.git') -Value 'gitdir: ../main/.git/worktrees/wt1' -Encoding utf8

            $r = Find-MshDiscoveryRoots -Path @($script:sandbox)
            $hit = @($r.Roots) | Where-Object { $_.Path -eq $repo }
            $hit.Count | Should -Be 1
        }

        It "reports type 'both' when .git and package.json coexist" {
            $proj = Join-Path $script:sandbox 'fullstack'
            New-Item -Path $proj -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path $proj '.git') -ItemType Directory -Force | Out-Null
            Set-Content -Path (Join-Path $proj 'package.json') -Value '{}' -Encoding utf8

            $r = Find-MshDiscoveryRoots -Path @($script:sandbox)
            $hit = @($r.Roots) | Where-Object { $_.Path -eq $proj }
            $hit[0].Type | Should -Be 'both'
        }
    }

    Context 'deny list' {

        It "does not descend into node_modules looking for nested projects" {
            $proj = Join-Path $script:sandbox 'app'
            New-Item -Path $proj -ItemType Directory -Force | Out-Null
            Set-Content -Path (Join-Path $proj 'package.json') -Value '{}' -Encoding utf8

            # A nested package.json inside node_modules — must NOT be reported as a root
            $nm = Join-Path (Join-Path $proj 'node_modules') 'some-dep'
            New-Item -Path $nm -ItemType Directory -Force | Out-Null
            Set-Content -Path (Join-Path $nm 'package.json') -Value '{}' -Encoding utf8

            $r = Find-MshDiscoveryRoots -Path @($script:sandbox)
            @($r.Roots).Path | Should -Contain $proj
            @($r.Roots).Path | Should -Not -Contain $nm
            $r.SkippedCounts.DenyList | Should -BeGreaterThan 0
        }

        It 'skips .git/objects and other VCS internals' {
            $repo = Join-Path $script:sandbox 'r'
            New-Item -Path $repo -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path $repo '.git') -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path (Join-Path $repo '.git') 'objects') -ItemType Directory -Force | Out-Null
            # A bogus package.json inside .git/objects should NOT be reported
            $bogus = Join-Path (Join-Path (Join-Path $repo '.git') 'objects') 'evil'
            New-Item -Path $bogus -ItemType Directory -Force | Out-Null
            Set-Content -Path (Join-Path $bogus 'package.json') -Value '{}' -Encoding utf8

            $r = Find-MshDiscoveryRoots -Path @($script:sandbox)
            @($r.Roots).Path | Should -Not -Contain $bogus
        }
    }

    Context 'bounding' {

        It 'respects MaxDepth' {
            # Build a chain deeper than depth=2
            $d1 = Join-Path $script:sandbox 'a'
            $d2 = Join-Path $d1 'b'
            $d3 = Join-Path $d2 'c'
            $d4 = Join-Path $d3 'd'  # depth 4 from sandbox
            New-Item -Path $d4 -ItemType Directory -Force | Out-Null
            Set-Content -Path (Join-Path $d4 'package.json') -Value '{}' -Encoding utf8

            $r = Find-MshDiscoveryRoots -Path @($script:sandbox) -MaxDepth 2
            @($r.Roots).Path | Should -Not -Contain $d4
            $r.SkippedCounts.DepthCap | Should -BeGreaterThan 0
        }

        It 'records DurationSec' {
            $r = Find-MshDiscoveryRoots -Path @($script:sandbox)
            $r.DurationSec | Should -BeGreaterOrEqual 0
        }
    }

    Context 'zero-roots case' {

        It 'returns an empty Roots list when nothing matches' {
            # sandbox has no .git and no package.json — and we don't create any
            $r = Find-MshDiscoveryRoots -Path @($script:sandbox)
            @($r.Roots).Count | Should -Be 0
        }
    }

    Context 'Windows-only — drive selection' -Skip:(-not $IsWindows) {

        It 'honors -ExcludeDrives' {
            # Without -Path, we'd walk all fixed+removable drives. Exclude a
            # likely-present letter and verify it shows up in SkippedDrives.
            $r = Find-MshDiscoveryRoots -ExcludeDrives @('C') -DiscoveryTimeoutSec 5 -PerDriveTimeoutSec 1 -PerTreeTimeoutSec 1
            $skipped = @($r.SkippedDrives | Where-Object { $_.Drive -eq 'C' })
            $skipped.Count | Should -BeGreaterThan 0
            $skipped[0].Reason | Should -Match 'ExcludeDrives'
        }
    }
}
