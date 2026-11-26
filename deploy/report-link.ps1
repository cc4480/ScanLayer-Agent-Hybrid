# Login-free public report link for a SecLayer scan (MCP flow).
#
# MCP scans authenticate with the local API key, which has no session and no
# share endpoint, so the app never mints a shareToken for them and the dashboard
# asks for a sign-in. This prints the /r/<shareToken> link instead.
#
#   powershell -ExecutionPolicy Bypass -File deploy\report-link.ps1
#   powershell -ExecutionPolicy Bypass -File deploy\report-link.ps1 -ScanId scan_abc123
#
# It reads the token; only when the scan has none does it mint one in the same
# format the app uses (shr_ + 32 hex) and write that single column.
[CmdletBinding()]
param(
    [string]$ScanId = "",
    [int]$Port = 4710
)
$ErrorActionPreference = "Stop"
$dq = [char]34

function Invoke-Sql([string]$q) {
    return ((& docker exec stack-db psql -U seclayer -d seclayer -tAc $q 2>&1) -join " ")
}

$where = if ($ScanId) { " where id = '" + $ScanId + "'" } else { "" }
$q = "select id, coalesce(" + $dq + "shareToken" + $dq + ", '-') from scans" + $where +
     " order by " + $dq + "createdAt" + $dq + " desc limit 1"
$row = (Invoke-Sql $q).Trim()
if (-not $row) { throw "No scan found. Run an MCP scan first." }

$parts = $row.Split([char]124)
$id = $parts[0]
$token = $parts[1]

if ($token -eq "-" -or [string]::IsNullOrWhiteSpace($token)) {
    $token = "shr_" + [guid]::NewGuid().ToString("N")
    $u = "update scans set " + $dq + "shareToken" + $dq + " = '" + $token + "' where id = '" + $id + "' and " + $dq + "shareToken" + $dq + " is null returning id"
    if (-not (Invoke-Sql $u)) { throw "Could not mint a share token for $id" }
}

$url = "http://127.0.0.1:$Port/r/$token"
$code = & curl.exe -s -o NUL -w "%{http_code}" --max-time 8 $url
Write-Host ""
Write-Host "scan : $id"
Write-Host "link : $url"
Write-Host "http : $code"
