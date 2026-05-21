function Invoke-LockfileAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectPath)

    $vulnAxios   = @('1.14.1', '0.30.4')
    $vulnCrypto  = '4.2.1'
    # Additional packages distributing the same plain-crypto-js malware
    $vulnOpenclaw = @('@shadanai/openclaw', '@qqbrowser/openclaw-qbot')
    $result = [PSCustomObject]@{
        ProjectPath             = $ProjectPath
        HasVulnerableAxios      = $false
        VulnerableAxiosVersion  = $null
        HasMaliciousPlainCrypto = $false
        HasMaliciousOpenclaw    = $false
        MaliciousPackageName    = $null
        LockfileType            = $null
        LockfilePath            = $null
        Error                   = $null
    }

    $lock = Get-LockfileText -ProjectPath $ProjectPath
    if (-not $lock.Type) { return $result }

    $result.LockfileType = $lock.Type
    $result.LockfilePath = $lock.Path
    if ($lock.Error)  { $result.Error = $lock.Error; return $result }
    $content = $lock.Content

    switch ($lock.Type) {
        'npm' {
            # In npm lockfiles (v1/v2/v3) "version" is always the first property after the package key.
            # Regex search avoids ConvertFrom-Json which is very slow on large lockfiles in PS5.1.
            foreach ($m in [regex]::Matches($content, '"(?:node_modules/)?axios"\s*:\s*\{[^"]*"version"\s*:\s*"([^"]+)"')) {
                if ($m.Groups[1].Value -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $m.Groups[1].Value }
            }
            foreach ($m in [regex]::Matches($content, '"(?:node_modules/)?plain-crypto-js"\s*:\s*\{[^"]*"version"\s*:\s*"([^"]+)"')) {
                if ($m.Groups[1].Value -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
            foreach ($pkg in $vulnOpenclaw) {
                $escaped = [regex]::Escape($pkg)
                if ($content -match "(?:node_modules/)?$escaped") {
                    $result.HasMaliciousOpenclaw = $true; $result.MaliciousPackageName = $pkg
                }
            }
        }
        'yarn' {
            foreach ($m in [regex]::Matches($content, '(?m)^axios@[^\n]+\n\s+version\s+"([^"]+)"')) {
                if ($m.Groups[1].Value -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $m.Groups[1].Value }
            }
            foreach ($m in [regex]::Matches($content, '(?m)^plain-crypto-js@[^\n]+\n\s+version\s+"([^"]+)"')) {
                if ($m.Groups[1].Value -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
            foreach ($pkg in $vulnOpenclaw) {
                $escaped = [regex]::Escape($pkg)
                if ($content -match "(?m)^`"?$escaped") {
                    $result.HasMaliciousOpenclaw = $true; $result.MaliciousPackageName = $pkg
                }
            }
        }
        'pnpm' {
            # pnpm-lock.yaml format: "  /axios/1.14.1:" or "  axios@1.14.1:"
            foreach ($m in [regex]::Matches($content, '(?m)^\s+(?:/|)axios[/@]([^\s:]+):')) {
                if ($m.Groups[1].Value -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $m.Groups[1].Value }
            }
            foreach ($m in [regex]::Matches($content, '(?m)^\s+(?:/|)plain-crypto-js[/@]([^\s:]+):')) {
                if ($m.Groups[1].Value -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
            foreach ($pkg in $vulnOpenclaw) {
                $escaped = [regex]::Escape($pkg)
                if ($content -match $escaped) {
                    $result.HasMaliciousOpenclaw = $true; $result.MaliciousPackageName = $pkg
                }
            }
        }
    }

    return $result
}
