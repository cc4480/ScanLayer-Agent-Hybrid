# open-superagent.ps1
# Opens the running superagent in the default browser with its current token.
# The token rotates on every server start; this reads the live one so no manual paste is needed.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File "<package root>\open-superagent.ps1"

$ErrorActionPreference = 'Stop'
$root    = $PSScriptRoot
$state   = Join-Path $root 'state'
$port    = 3082
$base    = "http://127.0.0.1:$port/"
$deskUrl = 'C:\Users\Cho-zen\OneDrive\Desktop\harness-superagent-url.txt'

# 1. The server must be listening on the superagent port.
$listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $listener) {
    Write-Host "superagent is not running on port $port. Start it with restart-superagent.ps1 first." -ForegroundColor Yellow
    exit 1
}

# 2. Find the most recent token URL the server printed at startup.
$pattern = [regex]('dsh web: (http://127\.0\.0\.1:' + $port + '/\?token=[A-Za-z0-9_\-]+)')
$logs = Get-ChildItem -LiteralPath $state -Filter 'superagent-restart-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
$url = $null
foreach ($log in $logs) {
    $m = $pattern.Match((Get-Content -LiteralPath $log.FullName -Raw))
    if ($m.Success) { $url = $m.Groups[1].Value; break }
}
if (-not $url) {
    Write-Host 'No startup token found in the superagent logs. Restart the superagent with restart-superagent.ps1.' -ForegroundColor Yellow
    exit 1
}

# 3. Keep the Desktop reference file current (so other tools read the live token).
Set-Content -LiteralPath $deskUrl -Value $url -Encoding UTF8

# 4. Open it. Windows opens the link as a direct navigation, which the server accepts.
Start-Process $url
Write-Host "Opened superagent on port $port (token rotated per server start)."
