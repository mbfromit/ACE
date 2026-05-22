#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private/Shared/New-Finding.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Find-MshWormWorkflow.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Find-MshPayloadFile.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Find-MshDropperArtifact.ps1')
    . (Join-Path $repoRoot 'Private/MiniShaiHulud/Find-MshTrufflehogDrop.ps1')

    # Minimal IOC bundle the checks consume. Real feed has more — these
    # tests focus on the fields each check actually reads.
    $script:iocs = [PSCustomObject]@{
        workflow_filenames    = @('shai-hulud-workflow.yml', 'shai-hulud.yml', 'shai-hulud.yaml')
        payload_filenames     = @('bundle.js')
        payload_hashes        = [PSCustomObject]@{ sha256 = @() }
        dropper_filenames     = @('processor.sh')
        dropper_drop_paths    = @('<tmp>', '<home>', '<node_project>')
        trufflehog_drop_paths = @()  # filled per-test
        attack_window_start   = '2026-04-01T00:00:00Z'
        attack_window_end     = $null
    }
}

Describe 'Find-MshWormWorkflow (Check 13)' {

    BeforeEach {
        $script:sandbox = Join-Path ([IO.Path]::GetTempPath()) "msh-c13-$(New-Guid)"
        $script:repo = Join-Path $script:sandbox 'myrepo'
        New-Item -Path (Join-Path $script:repo '.git') -ItemType Directory -Force | Out-Null
        $script:wfDir = Join-Path (Join-Path $script:repo '.github') 'workflows'
        New-Item -Path $script:wfDir -ItemType Directory -Force | Out-Null
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:sandbox) {
            Remove-Item -LiteralPath $script:sandbox -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns no findings on a clean repo' {
        Set-Content -Path (Join-Path $script:wfDir 'ci.yml') -Value 'name: ci' -Encoding utf8
        $r = @(Find-MshWormWorkflow -GitRoot $script:repo -Iocs $script:iocs)
        $r.Count | Should -Be 0
    }

    It 'fires CRITICAL on shai-hulud-workflow.yml' {
        $wf = Join-Path $script:wfDir 'shai-hulud-workflow.yml'
        Set-Content -Path $wf -Value "name: shai-hulud`non: push" -Encoding utf8
        $r = @(Find-MshWormWorkflow -GitRoot $script:repo -Iocs $script:iocs)
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'Critical'
        $r[0].Type | Should -Be 'WormWorkflowFile'
        $r[0].Path | Should -Be $wf
        $r[0].Excerpt | Should -Match 'shai-hulud'
    }

    It 'emits ScannerVerdict=Confirmed + UserAndManager isolation ActionRequired' {
        $wf = Join-Path $script:wfDir 'shai-hulud-workflow.yml'
        Set-Content -Path $wf -Value 'name: shai-hulud' -Encoding utf8
        $r = @(Find-MshWormWorkflow -GitRoot $script:repo -Iocs $script:iocs)
        $r[0].ScannerVerdict | Should -Be 'Confirmed'
        $r[0].ActionTarget   | Should -Be 'UserAndManager'
        $r[0].ActionRequired | Should -Match 'isolate this workstation'
        $r[0].ActionRequired | Should -Match 'runbook'
    }

    It "also catches the shai-hulud.yml variant" {
        Set-Content -Path (Join-Path $script:wfDir 'shai-hulud.yml') -Value 'name: x' -Encoding utf8
        $r = @(Find-MshWormWorkflow -GitRoot $script:repo -Iocs $script:iocs)
        $r.Count | Should -Be 1
    }

    It 'returns no findings when the workflows folder does not exist' {
        Remove-Item -LiteralPath $script:wfDir -Recurse -Force
        $r = @(Find-MshWormWorkflow -GitRoot $script:repo -Iocs $script:iocs)
        $r.Count | Should -Be 0
    }
}

Describe 'Find-MshPayloadFile (Check 14)' {

    BeforeEach {
        $script:proj = Join-Path ([IO.Path]::GetTempPath()) "msh-c14-$(New-Guid)"
        New-Item -Path $script:proj -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $script:proj 'package.json') -Value '{}' -Encoding utf8
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:proj) {
            Remove-Item -LiteralPath $script:proj -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns no findings when MatchedPackages is empty' {
        $r = @(Find-MshPayloadFile -NodeProjectRoot $script:proj -MatchedPackages @() -Iocs $script:iocs)
        $r.Count | Should -Be 0
    }

    It 'returns no findings when node_modules does not exist' {
        $r = @(Find-MshPayloadFile -NodeProjectRoot $script:proj -MatchedPackages @('mbt') -Iocs $script:iocs)
        $r.Count | Should -Be 0
    }

    It 'fires CRITICAL when bundle.js exists inside the matched package node_modules folder' {
        $pkgDir = Join-Path (Join-Path $script:proj 'node_modules') 'mbt'
        New-Item -Path $pkgDir -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $pkgDir 'bundle.js') -Value '/*malicious*/' -Encoding utf8

        $r = @(Find-MshPayloadFile -NodeProjectRoot $script:proj -MatchedPackages @('mbt') -Iocs $script:iocs)
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'Critical'
        $r[0].Type | Should -Be 'WormPayloadFile'
        $r[0].PackageName | Should -Be 'mbt'
        $r[0].PayloadName | Should -Be 'bundle.js'
        $r[0].ScannerVerdict | Should -Be 'Confirmed'
        $r[0].ActionTarget   | Should -Be 'UserAndManager'
        $r[0].ActionRequired | Should -Match 'isolate this workstation'
    }

    It 'handles scoped packages (@scope/name) correctly' {
        $pkgDir = Join-Path (Join-Path (Join-Path $script:proj 'node_modules') '@cap-js') 'sqlite'
        New-Item -Path $pkgDir -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $pkgDir 'bundle.js') -Value '/*malicious*/' -Encoding utf8

        $r = @(Find-MshPayloadFile -NodeProjectRoot $script:proj -MatchedPackages @('@cap-js/sqlite') -Iocs $script:iocs)
        $r.Count | Should -Be 1
        $r[0].PackageName | Should -Be '@cap-js/sqlite'
    }
}

Describe 'Find-MshDropperArtifact (Check 15)' {

    BeforeEach {
        $script:sandbox = Join-Path ([IO.Path]::GetTempPath()) "msh-c15-$(New-Guid)"
        New-Item -Path $script:sandbox -ItemType Directory -Force | Out-Null
        # IOC bundle scoped to this sandbox so the test doesn't accidentally
        # fire on a real processor.sh sitting in /tmp on the dev box.
        $script:scopedIocs = [PSCustomObject]@{
            dropper_filenames  = @('processor.sh')
            dropper_drop_paths = @('<node_project>')
            attack_window_start = $null
            attack_window_end   = $null
        }
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:sandbox) {
            Remove-Item -LiteralPath $script:sandbox -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns no findings on a clean project' {
        $r = @(Find-MshDropperArtifact -NodeProjectRoots @($script:sandbox) -Iocs $script:scopedIocs)
        $r.Count | Should -Be 0
    }

    It 'fires CRITICAL when processor.sh is dropped at a Node project root' {
        $dropper = Join-Path $script:sandbox 'processor.sh'
        Set-Content -Path $dropper -Value "#!/bin/sh`necho hi" -Encoding utf8

        $r = @(Find-MshDropperArtifact -NodeProjectRoots @($script:sandbox) -Iocs $script:scopedIocs)
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'Critical'
        $r[0].Type | Should -Be 'WormDropperArtifact'
        $r[0].Path | Should -Be $dropper
        $r[0].ScannerVerdict | Should -Be 'Confirmed'
        $r[0].ActionTarget   | Should -Be 'UserAndManager'
        $r[0].ActionRequired | Should -Match 'isolate this workstation'
    }
}

Describe 'Find-MshTrufflehogDrop (Check 16)' {

    BeforeEach {
        $script:sandbox = Join-Path ([IO.Path]::GetTempPath()) "msh-c16-$(New-Guid)"
        New-Item -Path $script:sandbox -ItemType Directory -Force | Out-Null
        $script:dropPath = Join-Path $script:sandbox 'trufflehog'
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:sandbox) {
            Remove-Item -LiteralPath $script:sandbox -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns no findings when the drop path is empty' {
        $iocs = [PSCustomObject]@{
            trufflehog_drop_paths = @($script:dropPath)
            attack_window_start   = '2026-04-01T00:00:00Z'
            attack_window_end     = $null
        }
        $r = @(Find-MshTrufflehogDrop -Iocs $iocs)
        $r.Count | Should -Be 0
    }

    It 'fires CRITICAL + Confirmed when binary mtime falls inside attack window' {
        Set-Content -Path $script:dropPath -Value 'fake binary' -Encoding utf8
        # Force the mtime to land squarely in the window
        (Get-Item -LiteralPath $script:dropPath).LastWriteTime = [datetime]::Parse('2026-05-01T12:00:00Z').ToLocalTime()

        $iocs = [PSCustomObject]@{
            trufflehog_drop_paths = @($script:dropPath)
            attack_window_start   = '2026-04-01T00:00:00Z'
            attack_window_end     = $null
        }
        $r = @(Find-MshTrufflehogDrop -Iocs $iocs)
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'Critical'
        $r[0].Type | Should -Be 'TrufflehogDrop'
        $r[0].InAttackWindow | Should -BeTrue
        $r[0].ScannerVerdict | Should -Be 'Confirmed'
        $r[0].ActionTarget   | Should -Be 'UserAndManager'
        $r[0].ActionRequired | Should -Match 'isolate this workstation'
    }

    It 'fires HIGH + Inconclusive when binary mtime is BEFORE the attack window starts' {
        Set-Content -Path $script:dropPath -Value 'fake binary' -Encoding utf8
        # Force mtime well before window start
        (Get-Item -LiteralPath $script:dropPath).LastWriteTime = [datetime]::Parse('2025-01-01T00:00:00Z').ToLocalTime()

        $iocs = [PSCustomObject]@{
            trufflehog_drop_paths = @($script:dropPath)
            attack_window_start   = '2026-04-01T00:00:00Z'
            attack_window_end     = $null
        }
        $r = @(Find-MshTrufflehogDrop -Iocs $iocs)
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'High'
        $r[0].InAttackWindow | Should -BeFalse
        $r[0].ScannerVerdict | Should -Be 'Inconclusive'
        $r[0].ActionTarget   | Should -Be 'Manager'
        $r[0].ActionRequired | Should -Match 'Did you install TruffleHog'
    }
}
