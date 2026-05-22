# Plaintext-secret scrubber for finding content.
#
# RATCATCHER captures free-form content (shell-history lines, package.json
# install hooks, workflow YAML excerpts) that on a real workstation can
# carry inline credentials -- NPM_TOKEN, GitHub PATs, AWS keys, Bearer
# tokens, basic-auth URLs. Those captures flow to R2 (full report HTML)
# and to D1 (first 500 chars stored on the AI verdict row).
#
# This redactor is the choke point: every finding the suite emits goes
# through New-Finding (the call-site immediately downstream), and
# New-Finding runs Remove-MshSecretsFromString on the free-form fields
# BEFORE the finding object is returned to the caller. The contract is
# "no plaintext credentials in the payload" -- this file is the enforcer.
#
# Adding patterns: append to $script:MshSecretPatterns. Keep the Kind
# string short (it appears in <REDACTED:kind> markers in the rendered
# report). Patterns are applied in the order listed; basic-auth URL has
# its own handling at the bottom because it preserves the URL scheme.

$script:MshSecretPatterns = @(
    # npm publish tokens — 36+ char base62 body after the prefix.
    @{ Kind = 'npm-token'        ; Pattern = 'npm_[A-Za-z0-9]{36,}' }

    # GitHub Personal Access Tokens — classic (ghp_), OAuth (gho_),
    # and fine-grained (github_pat_, 82-char body that includes underscores).
    @{ Kind = 'github-pat'       ; Pattern = 'ghp_[A-Za-z0-9]{36}' }
    @{ Kind = 'github-oauth'     ; Pattern = 'gho_[A-Za-z0-9]{36}' }
    @{ Kind = 'github-fine-pat'  ; Pattern = 'github_pat_[A-Za-z0-9_]{82}' }

    # AWS access key IDs — AKIA for long-lived IAM users, ASIA for
    # temporary STS credentials. 20-char total length.
    @{ Kind = 'aws-access-key'   ; Pattern = '(?:AKIA|ASIA)[0-9A-Z]{16}' }

    # AWS secret access key — only catchable contextually because the
    # 40-char body has no structural prefix. Case-insensitive on the
    # config-key name.
    @{ Kind = 'aws-secret-key'   ; Pattern = '(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}' }

    # Inline credential flags / env assignments commonly seen in npm
    # publish lines and CI config snippets. The \S+ swallows the value
    # to end-of-token; any trailing space terminates the match.
    @{ Kind = 'cli-token'        ; Pattern = '--token[= ]\S+' }
    @{ Kind = 'cli-otp'          ; Pattern = '--otp[= ]\S+' }
    @{ Kind = 'authtoken'        ; Pattern = '_authToken[= :]\S+' }
    @{ Kind = 'env-npm-token'    ; Pattern = 'NPM_TOKEN\s*=\s*\S+' }
    @{ Kind = 'env-github-token' ; Pattern = 'GITHUB_TOKEN\s*=\s*\S+' }

    # Bearer header — JWTs and opaque tokens. The 20-char floor avoids
    # catching the literal word "Bearer" followed by short non-secret
    # tokens (e.g. "Bearer null").
    @{ Kind = 'bearer'           ; Pattern = 'Bearer\s+[A-Za-z0-9._\-]{20,}' }
)

# Basic-auth URL is handled separately so we can preserve the scheme via
# a regex back-reference. The match covers scheme://user:pass@ — the
# host that follows is OUTSIDE the match and is preserved.
$script:MshBasicAuthUrlPattern = '(https?://)[^:\s/]+:[^@\s/]+@'

function Remove-MshSecretsFromString {
    <#
    .SYNOPSIS
        Replace known-shape secrets in a string with <REDACTED:kind> markers.

    .DESCRIPTION
        Idempotent. Returns input unchanged if it contains no recognized
        token shape. Each pattern is applied independently; multi-secret
        single lines are fully scrubbed.

        Callers check whether redaction fired by comparing input vs output
        ($before -ne $after). New-Finding does this and sets
        Extra.RedactionApplied = $true so the report can flag the finding
        as scrubbed.

    .OUTPUTS
        String. Empty/null input returns unchanged.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    foreach ($p in $script:MshSecretPatterns) {
        $Text = [regex]::Replace($Text, $p.Pattern, "<REDACTED:$($p.Kind)>")
    }

    # Basic-auth URL — preserve scheme, replace user:pass@ with marker.
    $Text = [regex]::Replace(
        $Text,
        $script:MshBasicAuthUrlPattern,
        '${1}<REDACTED:basic-auth>@'
    )

    return $Text
}
