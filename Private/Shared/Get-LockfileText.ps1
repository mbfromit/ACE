function Get-LockfileText {
    <#
    .SYNOPSIS
        Locate and read a Node project's lockfile (npm / yarn / pnpm).
    .DESCRIPTION
        Returns the lockfile contents plus its type. Both the Axios and Mini
        Shai-Hulud scanners consume this; each one applies its own IOC matchers
        against the returned $Content. No parsing or matching happens here —
        keep this function strictly about IO + detection of which lockfile is
        present, so the matcher logic stays separable.
    .PARAMETER ProjectPath
        Directory containing package.json. Lockfiles are expected as siblings.
    .OUTPUTS
        PSCustomObject with:
            ProjectPath  - the input path
            Type         - 'npm' | 'yarn' | 'pnpm' | $null (none found)
            Path         - full path to the chosen lockfile, or $null
            Content      - raw lockfile text, or $null on read failure
            Error        - exception message if read failed, else $null
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectPath)

    $result = [PSCustomObject]@{
        ProjectPath = $ProjectPath
        Type        = $null
        Path        = $null
        Content     = $null
        Error       = $null
    }

    $candidates = @(
        @{ Type = 'npm';  File = 'package-lock.json' },
        @{ Type = 'yarn'; File = 'yarn.lock'         },
        @{ Type = 'pnpm'; File = 'pnpm-lock.yaml'    }
    )

    foreach ($c in $candidates) {
        $path = Join-Path $ProjectPath $c.File
        if (Test-Path $path) {
            $result.Type = $c.Type
            $result.Path = $path
            try {
                $result.Content = Get-Content $path -Raw -ErrorAction Stop
            } catch {
                $result.Error = "Failed to read $($c.File): $_"
            }
            return $result
        }
    }

    return $result
}
