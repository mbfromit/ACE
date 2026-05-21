function Submit-ScanToApi {
    param(
        [string]$ApiUrl,
        [string]$Password,
        [string]$Hostname,
        [string]$Username,
        [string]$ScanTimestamp,
        [string]$Duration,
        [string]$Verdict,
        [int]$ProjectsScanned,
        [int]$VulnerableCount,
        [int]$CriticalCount,
        [string]$PathsScanned,
        [string]$BriefPath,
        [string]$ReportPath,
        # Campaign discriminator. Default 'axios' keeps existing scanner byte-identical.
        # Mini Shai-Hulud scanner passes 'mini-shai-hulud'. Server validates whitelist.
        [string]$Campaign = 'axios'
    )

    if ([string]::IsNullOrEmpty($Password)) {
        return @{ Status = 'skipped' }
    }

    try {
        # Build multipart/form-data manually with explicit CRLF bytes.
        # Required because: (1) Invoke-RestMethod -Form quotes the boundary which
        # Cloudflare Workers cannot parse, and (2) we need explicit control over
        # line endings for cross-platform compatibility (macOS/Linux/Windows).
        $boundary = [System.Guid]::NewGuid().ToString('N')
        $CRLF     = [byte[]]@(13, 10)  # explicit CR+LF bytes, not string literals
        $enc      = [System.Text.Encoding]::UTF8

        $ms = [System.IO.MemoryStream]::new()

        $fields = [ordered]@{
            password         = $Password
            hostname         = $Hostname
            username         = $Username
            scan_timestamp   = $ScanTimestamp
            duration         = $Duration
            verdict          = $Verdict
            projects_scanned = [string]$ProjectsScanned
            vulnerable_count = [string]$VulnerableCount
            critical_count   = [string]$CriticalCount
            paths_scanned    = $PathsScanned
            campaign         = $Campaign
        }

        foreach ($key in $fields.Keys) {
            $header = $enc.GetBytes("--$boundary")
            $ms.Write($header, 0, $header.Length); $ms.Write($CRLF, 0, 2)
            $disp = $enc.GetBytes("Content-Disposition: form-data; name=`"$key`"")
            $ms.Write($disp, 0, $disp.Length); $ms.Write($CRLF, 0, 2); $ms.Write($CRLF, 0, 2)
            $val = $enc.GetBytes($fields[$key])
            $ms.Write($val, 0, $val.Length); $ms.Write($CRLF, 0, 2)
        }

        foreach ($file in @(
            @{ Name = 'brief';  Path = $BriefPath  },
            @{ Name = 'report'; Path = $ReportPath }
        )) {
            $fileName  = [System.IO.Path]::GetFileName($file.Path)
            $fileBytes = [System.IO.File]::ReadAllBytes($file.Path)

            $header = $enc.GetBytes("--$boundary")
            $ms.Write($header, 0, $header.Length); $ms.Write($CRLF, 0, 2)
            $disp = $enc.GetBytes("Content-Disposition: form-data; name=`"$($file.Name)`"; filename=`"$fileName`"")
            $ms.Write($disp, 0, $disp.Length); $ms.Write($CRLF, 0, 2)
            $ctype = $enc.GetBytes("Content-Type: text/html")
            $ms.Write($ctype, 0, $ctype.Length); $ms.Write($CRLF, 0, 2); $ms.Write($CRLF, 0, 2)
            $ms.Write($fileBytes, 0, $fileBytes.Length); $ms.Write($CRLF, 0, 2)
        }

        $footer = $enc.GetBytes("--$boundary--")
        $ms.Write($footer, 0, $footer.Length); $ms.Write($CRLF, 0, 2)

        $body = $ms.ToArray()
        $ms.Dispose()

        $response = Invoke-RestMethod -Uri $ApiUrl -Method POST `
            -Body $body `
            -ContentType "multipart/form-data; boundary=$boundary"

        return @{ Status = 'success'; Id = $response.id }
    }
    catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { }
        if ($statusCode -eq 401) {
            return @{ Status = 'wrong-password' }
        }
        return @{ Status = 'error'; Message = $_.ToString() }
    }
}
