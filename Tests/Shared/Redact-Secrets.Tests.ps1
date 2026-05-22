#Requires -Version 7.0
BeforeAll {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    . (Join-Path $repoRoot 'Private/Shared/Redact-Secrets.ps1')
}

Describe 'Remove-MshSecretsFromString — input handling' {

    It 'returns null input unchanged' {
        Remove-MshSecretsFromString -Text $null | Should -BeNullOrEmpty
    }

    It 'returns empty string unchanged' {
        Remove-MshSecretsFromString -Text '' | Should -Be ''
    }

    It 'leaves plain English prose untouched (no false positives on token-like words)' {
        # Words that LOOK suggestive but have no token prefix should pass through.
        $prose = 'The npm package was published with a valid bearer of trust; Token authority verified.'
        Remove-MshSecretsFromString -Text $prose | Should -Be $prose
    }

    It 'leaves a token marker (already-redacted text) unchanged — idempotent' {
        $already = 'something <REDACTED:npm-token> here'
        Remove-MshSecretsFromString -Text $already | Should -Be $already
    }
}

Describe 'Remove-MshSecretsFromString — token shapes' {

    It 'redacts npm publish tokens (npm_ + 36+ char body)' {
        # 36 chars after the prefix
        $secret = 'npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $r = Remove-MshSecretsFromString -Text "publish with $secret now"
        $r | Should -Not -Match 'npm_a{36}'
        $r | Should -Match '<REDACTED:npm-token>'
    }

    It 'redacts classic GitHub PAT (ghp_)' {
        $secret = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $r = Remove-MshSecretsFromString -Text "Authorization: token $secret"
        $r | Should -Not -Match 'ghp_a{36}'
        $r | Should -Match '<REDACTED:github-pat>'
    }

    It 'redacts GitHub OAuth tokens (gho_)' {
        $secret = 'gho_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        Remove-MshSecretsFromString -Text $secret | Should -Be '<REDACTED:github-oauth>'
    }

    It 'redacts GitHub fine-grained PAT (github_pat_ + 82-char body)' {
        $body = ('a' * 82)
        $secret = "github_pat_$body"
        $r = Remove-MshSecretsFromString -Text $secret
        $r | Should -Be '<REDACTED:github-fine-pat>'
    }

    It 'redacts AWS access key ID (AKIA + 16 alphanumeric)' {
        $secret = 'AKIAABCDEFGHIJKLMNOP'
        $r = Remove-MshSecretsFromString -Text "id=$secret"
        $r | Should -Not -Match $secret
        $r | Should -Match '<REDACTED:aws-access-key>'
    }

    It 'redacts AWS temporary credential ID (ASIA + 16 alphanumeric)' {
        $secret = 'ASIAABCDEFGHIJKLMNOP'
        Remove-MshSecretsFromString -Text $secret | Should -Be '<REDACTED:aws-access-key>'
    }

    It 'redacts AWS secret access key when keyed by config-line context (case-insensitive)' {
        $body = ('a' * 40)
        $line = "aws_secret_access_key = $body"
        $r = Remove-MshSecretsFromString -Text $line
        $r | Should -Not -Match $body
        $r | Should -Match '<REDACTED:aws-secret-key>'
    }

    It 'redacts --token CLI flag with both = and space separators' {
        Remove-MshSecretsFromString -Text 'npm publish --token=abc123def456' | Should -Match '<REDACTED:cli-token>'
        Remove-MshSecretsFromString -Text 'npm publish --token abc123def456'  | Should -Match '<REDACTED:cli-token>'
    }

    It 'redacts --otp CLI flag' {
        Remove-MshSecretsFromString -Text 'npm publish --otp 123456' | Should -Match '<REDACTED:cli-otp>'
    }

    It 'redacts _authToken in .npmrc-style lines' {
        $line = '//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
        $r = Remove-MshSecretsFromString -Text $line
        # Either the authtoken pattern OR the npm-token pattern (whichever
        # fires first) scrubs the secret -- the contract is no raw secret left.
        $r | Should -Not -Match 'npm_x{36}'
    }

    It 'redacts NPM_TOKEN env assignment' {
        $line = 'NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx npm publish'
        $r = Remove-MshSecretsFromString -Text $line
        $r | Should -Not -Match 'npm_x{36}'
        $r | Should -Match '<REDACTED:'
    }

    It 'redacts GITHUB_TOKEN env assignment' {
        $line = 'GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $r = Remove-MshSecretsFromString -Text $line
        $r | Should -Not -Match 'ghp_a{36}'
    }

    It 'redacts Bearer header with 20+ char token body' {
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig'
        Remove-MshSecretsFromString -Text "Authorization: Bearer $jwt" | Should -Match '<REDACTED:bearer>'
    }

    It 'does NOT redact "Bearer" with short non-secret value (under 20 chars)' {
        # Defensive: a literal "Bearer null" or "Bearer test" should not redact.
        Remove-MshSecretsFromString -Text 'Bearer null' | Should -Be 'Bearer null'
        Remove-MshSecretsFromString -Text 'Bearer test' | Should -Be 'Bearer test'
    }

    It 'redacts basic-auth URL while preserving scheme + host' {
        # Realistic basic-auth — special chars in real passwords are URL-
        # encoded (e.g. `@` -> `%40`) per RFC 3986. The redactor stops at the
        # first literal `@` because that's the userinfo terminator.
        $url = 'https://alice:s3cretP%40ss@registry.example.com/api'
        $r = Remove-MshSecretsFromString -Text "fetch $url please"
        $r | Should -Not -Match 'alice'
        $r | Should -Not -Match 's3cret'
        $r | Should -Match 'https://<REDACTED:basic-auth>@registry\.example\.com'
    }

    It 'preserves http scheme on basic-auth URL (not just https)' {
        $url = 'http://user:secret@internal-registry/api'
        Remove-MshSecretsFromString -Text $url | Should -Match 'http://<REDACTED:basic-auth>@internal-registry'
    }
}

Describe 'Remove-MshSecretsFromString — multi-secret single line' {

    It 'redacts every secret on a line containing multiple tokens' {
        $npm    = 'npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $ghp    = 'ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        $bearer = 'Bearer ccccccccccccccccccccccccc'
        $aws    = 'AKIA0123456789ABCDEF'
        $line = "echo $npm && curl -H 'Authorization: $bearer' && export GITHUB=$ghp aws=$aws"
        $r = Remove-MshSecretsFromString -Text $line
        $r | Should -Not -Match 'npm_a{36}'
        $r | Should -Not -Match 'ghp_b{36}'
        $r | Should -Not -Match 'AKIA'
        $r | Should -Not -Match 'ccccccccccccccccccccccccc'
        ([regex]::Matches($r, '<REDACTED:')).Count | Should -BeGreaterOrEqual 4
    }
}
