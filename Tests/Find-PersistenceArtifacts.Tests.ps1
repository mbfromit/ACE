BeforeAll {
    . "$PSScriptRoot/../Private/Find-PersistenceArtifacts.ps1"
    $attackStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
}

# Axios Find-PersistenceArtifacts is Windows-only by design (Get-ScheduledTask,
# HKCU:/HKLM: registry hives). Mocks reference cmdlets and drives that don't
# exist in non-Windows PowerShell sessions, so Pester can't bind them. Skip.
Describe 'Find-PersistenceArtifacts' -Skip:(-not $IsWindows) {
    Context 'suspicious scheduled task registered after attack' {
        BeforeAll {
            Mock Get-ScheduledTask {
                @([PSCustomObject]@{
                    TaskName  = 'WindowsUpdateHelper'
                    TaskPath  = '\'
                    State     = 'Ready'
                    Actions   = @([PSCustomObject]@{ Execute = 'powershell.exe'; Arguments = '-WindowStyle Hidden -File C:\Users\user\AppData\Local\Temp\a1b2c3.ps1' })
                    Date      = $attackStart.AddHours(2).ToString('o')
                })
            }
        }
        It 'returns a SuspiciousScheduledTask finding' {
            $results = Find-PersistenceArtifacts -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'SuspiciousScheduledTask') | Should -Not -BeNullOrEmpty
        }
        It 'severity is Critical' {
            $results = Find-PersistenceArtifacts -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'SuspiciousScheduledTask').Severity | Should -Be 'Critical'
        }
    }

    Context 'registry Run key with temp-path value added after attack' {
        BeforeAll {
            Mock Get-ItemProperty {
                [PSCustomObject]@{
                    PSPath       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
                    'NodeHelper' = 'C:\Users\user\AppData\Local\Temp\node_helper.exe'
                }
            } -ParameterFilter { $Path -match 'Run' }
        }
        It 'returns a SuspiciousRunKey finding' {
            $results = Find-PersistenceArtifacts -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'SuspiciousRunKey') | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Microsoft Store app (WindowsApps) Run key is not flagged' {
        BeforeAll {
            Mock Get-ScheduledTask { @() }
            Mock Get-ItemProperty {
                [PSCustomObject]@{
                    PSPath  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
                    'Teams' = '"C:\Users\user\AppData\Local\Microsoft\WindowsApps\MSTeams_8wekyb3d8bbwe\ms-teams.exe" msteams:system-initiated'
                }
            } -ParameterFilter { $Path -match 'Run' }
        }
        It 'does not flag ms-teams.exe in WindowsApps as a suspicious Run key' {
            Find-PersistenceArtifacts -AttackWindowStart $attackStart | Should -BeNullOrEmpty
        }
    }

    Context 'no suspicious entries' {
        BeforeAll {
            Mock Get-ScheduledTask { @() }
            Mock Get-ItemProperty  { [PSCustomObject]@{ PSPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' } }
        }
        It 'returns empty without throwing' {
            { Find-PersistenceArtifacts -AttackWindowStart $attackStart } | Should -Not -Throw
            Find-PersistenceArtifacts -AttackWindowStart $attackStart    | Should -BeNullOrEmpty
        }
    }
}
