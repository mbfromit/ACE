function Find-MshDiscoveryRoots {
    <#
    .SYNOPSIS
        Phase 1 discovery walker for the Mini Shai-Hulud bounded-detection scan.
    .DESCRIPTION
        Walks reachable filesystem looking for two markers — `.git` (file or
        directory) and `package.json` — and returns the parent directories as
        candidate roots for Phase 2 surgical IOC probes.

        The walk is bounded by three independent wall-clock caps (per-tree,
        per-drive, overall) plus a depth limit and a deny-list of folder names
        that cannot host new project roots (node_modules, system dirs, vendored
        dep caches, etc.). Reparse points and cloud-sync placeholder files are
        skipped — both are known to either loop forever or trigger surprise
        cloud downloads.

        Returns a diagnostics object that the report header consumes so a
        manager can audit "we looked where we said we'd look."

    .PARAMETER Path
        User-supplied starting roots. When provided, **replaces** the default
        per-OS roots entirely. Useful for testing or for narrow scope on
        machines where the user knows where their code lives.
    .PARAMETER ExcludeDrives
        Drive letters to skip on Windows (e.g. 'D','E'). The default is
        "scan all fixed + removable drives" — this knob is for the case where
        the user knows a specific drive is pure media/backup with no code.
    .PARAMETER IncludeNetworkDrives
        Off by default. Network drives have unpredictable latency and rarely
        host local code.
    .PARAMETER DiscoveryTimeoutSec
        Overall wall-clock budget. Default 300 (5 min).
    .PARAMETER PerDriveTimeoutSec
        Wall-clock budget per drive. Default 180 (3 min).
    .PARAMETER PerTreeTimeoutSec
        Wall-clock budget per top-level subtree. Default 90s.
    .PARAMETER MaxDepth
        Max directory depth from each starting root. Default 6. Real project
        roots sit near the surface; going deeper costs time without adding
        coverage.
    .OUTPUTS
        [PSCustomObject] with fields:
            Roots         — array of @{ Path, Type ('git_repo'|'node_project'|'both'), Drive }
            ScannedDrives — drive letters / mount points actually scanned
            PartialDrives — drives where a cap fired before the walk completed
            SkippedDrives — drives skipped entirely (excluded / network / not ready)
            SkippedCounts — @{ DenyList, ReparsePoints, CloudPlaceholders, DepthCap, AccessDenied }
            DurationSec   — total wall-clock
            HitOverallCap — bool, true if the global 5-min cap fired
    #>
    [CmdletBinding()]
    param(
        [string[]]$Path,
        [string[]]$ExcludeDrives = @(),
        [switch]$IncludeNetworkDrives,
        [int]$DiscoveryTimeoutSec = 300,
        [int]$PerDriveTimeoutSec  = 180,
        [int]$PerTreeTimeoutSec   = 90,
        [int]$MaxDepth            = 6
    )

    # ── Deny list (case-insensitive folder-name match) ────────────────────────
    # Folders that cannot host a new project root. Some (node_modules, .git)
    # the scan WILL probe directly later — we just don't *recurse into them*
    # looking for markers. That's the whole point: surgical probes, not walks.
    # Folder-name match only — no substring scanning. The walker descends
    # toward project roots; once it finds a marker (.git, package.json) it
    # records the root and stops recursing INTO that root's vendor/cache
    # subfolders. The deny list is the catalog of those non-descendable names.
    $denyExact = @(
        # VCS internals — once we see `.git` at a parent we record the parent
        # as a git_repo; descending into `.git/` itself never finds new projects
        '.git', '.svn', '.hg',
        # Node
        'node_modules', '.pnpm', '.yarn', 'bower_components',
        # Python
        'site-packages', '.venv', 'venv', '__pycache__', '.tox', '.pytest_cache', '.mypy_cache', '.ruff_cache',
        # JVM / Rust / Go / Ruby / PHP
        'target', 'build', '.gradle', 'vendor', '.bundle',
        # iOS / web build
        'Pods', 'Carthage', 'DerivedData', '.next', '.nuxt', '.svelte-kit', '.parcel-cache', '.turbo', '.cache', 'dist', 'out',
        # Windows system + per-user caches we never want to recurse into
        # (token files inside AppData are checked by direct-path helpers, not
        # by walking AppData)
        'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData', '$Recycle.Bin', 'System Volume Information',
        'WinSxS', 'Installer', 'SoftwareDistribution', 'AppData',
        # macOS system + per-user caches (token files in ~/.aws etc. are
        # checked by direct-path helpers; we don't walk Library)
        'System', 'Applications', 'private', 'Library', '.Trash'
    )
    $denySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $denyExact) { [void]$denySet.Add($n) }

    # ── Diagnostics accumulator ───────────────────────────────────────────────
    $diag = [ordered]@{
        Roots         = New-Object System.Collections.Generic.List[object]
        ScannedDrives = New-Object System.Collections.Generic.List[string]
        PartialDrives = New-Object System.Collections.Generic.List[object]
        SkippedDrives = New-Object System.Collections.Generic.List[object]
        SkippedCounts = @{ DenyList = 0; ReparsePoints = 0; CloudPlaceholders = 0; DepthCap = 0; AccessDenied = 0 }
        DurationSec   = 0
        HitOverallCap = $false
    }

    $overallSw = [System.Diagnostics.Stopwatch]::StartNew()

    # ── Resolve starting roots ────────────────────────────────────────────────
    # Each entry is @{ Path = '<abs>'; Drive = '<id>' }. Drive is just a label
    # for diagnostics — it's the drive letter on Windows, the volume name on
    # Mac, or '/' on Linux.
    $startRoots = New-Object System.Collections.Generic.List[object]

    if ($Path -and $Path.Count -gt 0) {
        foreach ($p in $Path) {
            if ($p -and (Test-Path -LiteralPath $p)) {
                $startRoots.Add(@{ Path = (Resolve-Path -LiteralPath $p).Path; Drive = '(user)' }) | Out-Null
            }
        }
    } else {
        if ($IsWindows -or ($null -eq $IsWindows -and $env:OS -eq 'Windows_NT')) {
            # DriveType 2 = removable, 3 = fixed, 4 = network
            $drives = @()
            try {
                $drives = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop |
                          Where-Object { $_.DriveType -in 2,3,4 }
            } catch {
                # Fallback: Get-PSDrive can't see DriveType, so include all FS drives
                $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
                          ForEach-Object {
                              [PSCustomObject]@{
                                  DeviceID  = ($_.Name + ':')
                                  DriveType = 3  # assume fixed; user can -ExcludeDrives if wrong
                              }
                          }
            }
            foreach ($d in $drives) {
                $letter = $d.DeviceID.TrimEnd(':')
                if ($ExcludeDrives -contains $letter) {
                    $diag.SkippedDrives.Add(@{ Drive = $letter; Reason = 'user -ExcludeDrives' }) | Out-Null
                    continue
                }
                if ($d.DriveType -eq 4 -and -not $IncludeNetworkDrives) {
                    $diag.SkippedDrives.Add(@{ Drive = $letter; Reason = 'network drive (use -IncludeNetworkDrives)' }) | Out-Null
                    continue
                }
                $root = $d.DeviceID + '\'
                if (-not (Test-Path -LiteralPath $root)) {
                    $diag.SkippedDrives.Add(@{ Drive = $letter; Reason = 'not ready / not mounted' }) | Out-Null
                    continue
                }
                $startRoots.Add(@{ Path = $root; Drive = $letter }) | Out-Null
            }
        }
        elseif ($IsMacOS) {
            $candidates = @($HOME, '/opt', '/srv')
            if (Test-Path -LiteralPath '/Volumes') {
                Get-ChildItem -LiteralPath '/Volumes' -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSIsContainer } |
                    ForEach-Object { $candidates += $_.FullName }
            }
            foreach ($c in $candidates) {
                if (Test-Path -LiteralPath $c) {
                    $startRoots.Add(@{ Path = $c; Drive = $c }) | Out-Null
                }
            }
        }
        else {
            # Linux
            $candidates = @($HOME, '/opt', '/srv')
            foreach ($base in @('/media','/mnt')) {
                if (Test-Path -LiteralPath $base) {
                    Get-ChildItem -LiteralPath $base -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSIsContainer } |
                        ForEach-Object { $candidates += $_.FullName }
                }
            }
            foreach ($c in $candidates) {
                if (Test-Path -LiteralPath $c) {
                    $startRoots.Add(@{ Path = $c; Drive = $c }) | Out-Null
                }
            }
        }
    }

    # ── Helpers ───────────────────────────────────────────────────────────────
    function Test-MshReparsePoint {
        param([System.IO.DirectoryInfo]$dir)
        try {
            return ($dir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint
        } catch { return $false }
    }

    function Test-MshCloudPlaceholder {
        param([System.IO.FileSystemInfo]$item)
        try {
            $attrs = [int]$item.Attributes
            # FILE_ATTRIBUTE_OFFLINE = 0x1000 ; FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
            if (($attrs -band 0x1000)   -eq 0x1000)   { return $true }
            if (($attrs -band 0x400000) -eq 0x400000) { return $true }
            # macOS / iCloud — files appear with .icloud extension when stubbed
            if ($item.Name -like '*.icloud') { return $true }
        } catch { }
        return $false
    }

    function Test-MshDenied {
        param([string]$name)
        return $denySet.Contains($name)
    }

    # ── Walk each starting root ───────────────────────────────────────────────
    foreach ($r in $startRoots) {
        if ($overallSw.Elapsed.TotalSeconds -ge $DiscoveryTimeoutSec) {
            $diag.HitOverallCap = $true
            $diag.SkippedDrives.Add(@{ Drive = $r.Drive; Reason = 'overall discovery cap reached before this drive started' }) | Out-Null
            continue
        }

        $diag.ScannedDrives.Add($r.Drive) | Out-Null
        $driveSw = [System.Diagnostics.Stopwatch]::StartNew()
        $driveHitCap = $false

        # BFS queue: each entry is @{ Path; Depth }
        $queue = New-Object System.Collections.Generic.Queue[object]
        $queue.Enqueue(@{ Path = $r.Path; Depth = 0; TreeStart = $driveSw.Elapsed })

        while ($queue.Count -gt 0) {
            if ($overallSw.Elapsed.TotalSeconds -ge $DiscoveryTimeoutSec) {
                $diag.HitOverallCap = $true; $driveHitCap = $true; break
            }
            if ($driveSw.Elapsed.TotalSeconds -ge $PerDriveTimeoutSec) {
                $driveHitCap = $true; break
            }

            $cur = $queue.Dequeue()

            # Per-tree cap (relative to when this top-level subtree started)
            if (($driveSw.Elapsed - $cur.TreeStart).TotalSeconds -ge $PerTreeTimeoutSec) {
                # Drop this subtree and continue — don't kill the whole drive
                continue
            }

            $curPath = $cur.Path
            $depth   = $cur.Depth

            # Get directory info safely
            $dirInfo = $null
            try { $dirInfo = [System.IO.DirectoryInfo]::new($curPath) } catch { continue }
            if (-not $dirInfo.Exists) { continue }

            # Skip reparse points (junctions, symlinks)
            if (Test-MshReparsePoint $dirInfo) {
                $diag.SkippedCounts.ReparsePoints++
                continue
            }

            # Skip cloud placeholders (whole directory stubbed)
            if (Test-MshCloudPlaceholder $dirInfo) {
                $diag.SkippedCounts.CloudPlaceholders++
                continue
            }

            # Check markers at this directory
            $hasGit  = $false
            $hasNode = $false
            try {
                # `.git` can be a directory OR a file (worktree pointer)
                if (Test-Path -LiteralPath (Join-Path $curPath '.git')) { $hasGit = $true }
                if (Test-Path -LiteralPath (Join-Path $curPath 'package.json')) {
                    # Verify the package.json isn't itself a cloud placeholder
                    $pj = Get-Item -LiteralPath (Join-Path $curPath 'package.json') -Force -ErrorAction SilentlyContinue
                    if ($pj -and -not (Test-MshCloudPlaceholder $pj)) { $hasNode = $true }
                    else { $diag.SkippedCounts.CloudPlaceholders++ }
                }
            } catch { }

            if ($hasGit -or $hasNode) {
                $type = if ($hasGit -and $hasNode) { 'both' } elseif ($hasGit) { 'git_repo' } else { 'node_project' }
                $diag.Roots.Add([PSCustomObject]@{
                    Path  = $curPath
                    Type  = $type
                    Drive = $r.Drive
                }) | Out-Null
            }

            # Depth cap — don't enqueue children past MaxDepth
            if ($depth -ge $MaxDepth) {
                $diag.SkippedCounts.DepthCap++
                continue
            }

            # Enumerate subdirectories
            $subs = $null
            try {
                $subs = $dirInfo.EnumerateDirectories()
            } catch [System.UnauthorizedAccessException] {
                $diag.SkippedCounts.AccessDenied++; continue
            } catch { continue }

            foreach ($sub in $subs) {
                try {
                    if (Test-MshDenied -name $sub.Name) {
                        $diag.SkippedCounts.DenyList++
                        continue
                    }
                    $queue.Enqueue(@{ Path = $sub.FullName; Depth = $depth + 1; TreeStart = $cur.TreeStart })
                } catch { continue }
            }
        }

        if ($driveHitCap) {
            $diag.PartialDrives.Add(@{
                Drive       = $r.Drive
                ElapsedSec  = [Math]::Round($driveSw.Elapsed.TotalSeconds, 1)
                Reason      = if ($diag.HitOverallCap) { 'overall cap' } else { 'per-drive cap' }
            }) | Out-Null
        }
    }

    $overallSw.Stop()

    # Convert internal Generic.List[object] accumulators to plain arrays before
    # returning. Callers (and Pester) routinely do @($result.Roots).Count — and
    # wrapping a generic List with @() trips PowerShell into "Argument types do
    # not match." Plain object[] arrays don't have that issue.
    return [PSCustomObject]@{
        Roots         = $diag.Roots.ToArray()
        ScannedDrives = $diag.ScannedDrives.ToArray()
        PartialDrives = $diag.PartialDrives.ToArray()
        SkippedDrives = $diag.SkippedDrives.ToArray()
        SkippedCounts = $diag.SkippedCounts
        DurationSec   = [Math]::Round($overallSw.Elapsed.TotalSeconds, 1)
        HitOverallCap = $diag.HitOverallCap
    }
}
