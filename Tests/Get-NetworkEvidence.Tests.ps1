BeforeAll {
    . "$PSScriptRoot/../Private/Get-NetworkEvidence.ps1"
}

# Axios Get-NetworkEvidence is Windows-only by design (Get-NetTCPConnection,
# ipconfig /displaydns). The tests mock cmdlets that don't exist in non-Windows
# PowerShell sessions, so Pester's Mock fails to bind. Skip on Mac/Linux.
Describe 'Get-NetworkEvidence' -Skip:(-not $IsWindows) {
    Context 'C2 IP in active TCP connections' {
        BeforeAll {
            Mock Get-NetTCPConnection {
                @([PSCustomObject]@{ RemoteAddress = '142.11.206.73'; RemotePort = 8000; State = 'Established'; OwningProcess = 1234 })
            }
            Mock Get-Process { [PSCustomObject]@{ Id = 1234; Name = 'node'; Path = 'C:\Program Files\nodejs\node.exe' } }
        }
        It 'returns ActiveC2Connection finding' {
            $results = Get-NetworkEvidence
            ($results | Where-Object Type -eq 'ActiveC2Connection') | Should -Not -BeNullOrEmpty
        }
        It 'severity is Critical' {
            $results = Get-NetworkEvidence
            ($results | Where-Object Type -eq 'ActiveC2Connection').Severity | Should -Be 'Critical'
        }
    }

    Context 'C2 domain in DNS cache' {
        BeforeAll {
            Mock Get-NetTCPConnection { @() }
            Mock Invoke-Expression {
                "Entry                   : sfrclak.com`n  Name      : sfrclak.com`n  Type      : 1`n  TTL       : 300"
            } -ParameterFilter { $Command -match 'ipconfig' }
        }
        It 'returns DnsCacheHit finding' {
            $results = Get-NetworkEvidence
            ($results | Where-Object Type -eq 'DnsCacheHit') | Should -Not -BeNullOrEmpty
        }
        It 'severity is High' {
            $results = Get-NetworkEvidence
            ($results | Where-Object Type -eq 'DnsCacheHit').Severity | Should -Be 'High'
        }
    }

    Context 'C2 IP in firewall log' {
        BeforeAll {
            Mock Get-NetTCPConnection { @() }
            Mock Invoke-Expression    { '' } -ParameterFilter { $Command -match 'ipconfig' }
            $fwLog = Join-Path $TestDrive 'pfirewall.log'
            "2026-03-31 01:15:33 ALLOW TCP 10.0.0.5 142.11.206.73 49123 8000 1 - - - - - - - SEND" | Set-Content $fwLog
            Mock Get-Item { [PSCustomObject]@{ FullName = $fwLog } } -ParameterFilter { $Path -match 'pfirewall' }
        }
        It 'returns FirewallLogHit finding' {
            $results = Get-NetworkEvidence -FirewallLogPath (Join-Path $TestDrive 'pfirewall.log')
            ($results | Where-Object Type -eq 'FirewallLogHit') | Should -Not -BeNullOrEmpty
        }
    }

    Context 'clean network state' {
        BeforeAll {
            Mock Get-NetTCPConnection { @() }
            Mock Invoke-Expression    { 'no entries' } -ParameterFilter { $Command -match 'ipconfig' }
        }
        It 'returns empty without throwing' {
            { Get-NetworkEvidence } | Should -Not -Throw
            Get-NetworkEvidence    | Should -BeNullOrEmpty
        }
    }
}
