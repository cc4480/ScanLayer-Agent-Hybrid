# restart-superagent.ps1 - stop and relaunch the superagent profile server (port 3082)
#
# Reloads .dsh\profiles\superagent\cordis.patch.yml, which is how the AlterEgo
# MCP server entry becomes live as native mcp__alterego__* tools.
#
#   .\restart-superagent.ps1            stop, relaunch, print the new tokenized URL
#   .\restart-superagent.ps1 -DryRun    show what would be stopped / run
#
# Needs an elevated PowerShell: the running server may have been started from a
# higher-integrity process, and a non-elevated shell cannot read its command line
# or terminate it (Access is denied / "no process found").
#
# The Web UI at 3082 needs the NEW ?token= URL this script prints. Sessions are
# durable: reopening the same session keeps its history.
param(
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$HarnessDir = Join-Path $Root 'src\deepseek-harness'
$LogDir = Join-Path $Root 'state'
$LogFile = Join-Path $LogDir 'superagent-restart.log'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Get-PortOwner([int]$port) {
    $line = netstat -ano | Select-String ":$port\s+.*LISTENING" | Select-Object -First 1
    if (-not $line) { return $null }
    $fields = ($line.Line -split '\s+') | Where-Object { $_ }
    return [int]$fields[-1]
}

$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) {
    Write-Host 'This must run elevated (right-click PowerShell -> Run as administrator, or:' -ForegroundColor Yellow
    Write-Host '  Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File ""' + $PSCommandPath + '"""' -ForegroundColor Yellow
    return
}

$owner = Get-PortOwner 3082
if ($owner) {
    $proc = Get-Process -Id $owner -ErrorAction SilentlyContinue
    Write-Host "port 3082 is held by pid $owner ($($proc.ProcessName)) - stopping it"
    if ($DryRun) {
        Write-Host "would run: cd `"$HarnessDir`" ; pnpm dsh --profile superagent --no-open  (log: $LogFile)"
        return
    }
    try {
        Stop-Process -Id $owner -Force -ErrorAction Stop
    } catch {
        Write-Host "could not stop pid $owner : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'run this script from an elevated PowerShell' -ForegroundColor Yellow
        return
    }
} else {
    Write-Host 'port 3082 is free - launching a fresh server'
    if ($DryRun) {
        Write-Host "would run: cd `"$HarnessDir`" ; pnpm dsh --profile superagent --no-open  (log: $LogFile)"
        return
    }
}

for ($i = 0; $i -lt 40; $i++) {
    if (-not (Get-PortOwner 3082)) { break }
    Start-Sleep -Milliseconds 500
}

# pnpm is launched through cmd so PowerShell's execution policy does not apply.
$env:DSH_HOME = Join-Path $Root '.dsh'
Remove-Item $LogFile -Force -ErrorAction SilentlyContinue
$cmd = "cd /d `"$HarnessDir`" && pnpm dsh --profile superagent --no-open > `"$LogFile`" 2>&1"
Start-Process cmd -ArgumentList '/c', $cmd -WindowStyle Hidden

$url = $null
for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 2
    if (Test-Path $LogFile) {
        $m = Select-String -Path $LogFile -Pattern 'https?://127\.0\.0\.1:3082/\?token=\S+' -ErrorAction SilentlyContinue |
            Select-Object -Last 1
        if ($m) { $url = $m.Matches[0].Value; break }
        if (Select-String -Path $LogFile -Pattern 'Failed plugins|startup failed|ELIFECYCLE' -Quiet) { break }
    }
}

Set-Content -Path (Join-Path $LogDir 'superagent-url.txt') -Value ($url ?? 'no url captured') -Encoding UTF8

if ($url) {
    Write-Host ''
    Write-Host 'superagent server is back up. Open this URL (new token):' -ForegroundColor Green
    Write-Host "  $url" -ForegroundColor Cyan
    Set-Clipboard -Value $url
    Write-Host '(copied to clipboard)'
} else {
    Write-Host "server did not come up - last log lines from $LogFile" -ForegroundColor Red
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 25 }
}
