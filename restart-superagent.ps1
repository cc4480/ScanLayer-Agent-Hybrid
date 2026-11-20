# restart-superagent.ps1 - stop and relaunch the superagent profile server (default port 3082)
#
# Reloads .dsh\profiles\superagent\cordis.patch.yml (how the AlterEgo MCP server entry
# becomes live as native mcp__alterego__* tools) and picks up a rebuilt
# src\dsh-superagent-prototype\lib.
#
#   .\restart-superagent.ps1            stop (if running), relaunch, verify, print the new tokenized URL
#   .\restart-superagent.ps1 -DryRun    show what would be stopped / run, change nothing
#
# Works in Windows PowerShell 5.1 and in PowerShell 7. A regular shell is enough when the
# running server was started by the same user at the same integrity level; if it was
# started elevated, the script says so and must be run elevated.
#
# SUCCESS means all of: the server printed its URL, the port is listening, the listener is
# the process this script launched (command line matches -OwnerPattern), and it is still
# listening after an 8 second settle check. A URL printed by a server that then died is a
# failure, and the URL file is overwritten with 'no url captured' so a dead token never
# lingers. Every launch writes its own log (superagent-restart-<time>.log, last 5 kept), so
# output of an older, dying server can never be mistaken for the new one.
#
# SAFETY: the script only stops the owner of the port when that process's command line
# matches -OwnerPattern. Anything else on the port is left alone and reported.
#
# Exit codes: 0 up and verified | 1 did not come up | 2 refused (foreign owner, or cannot stop it) | 3 timed out
#
# The Web UI needs the NEW ?token= URL this script prints. Sessions are durable: reopening
# the same session keeps its history.
#
# A force-stopped server leaves its state-directory lock (state\superagent.lock) behind until it
# goes stale after 30 s; the script waits for that (up to 45 s) before launching, otherwise the
# plugin fails with "Lock file is already being held".
#
# Test parameters (leave alone in normal use): -Port -LaunchCommand -OwnerPattern -UrlFile -LogDir -LockPath -NoClipboard
[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$Port = 3082,
    [string]$LaunchCommand = 'pnpm dsh --profile superagent --no-open',
    [string]$OwnerPattern = '--profile superagent',
    [int]$TimeoutSeconds = 180,
    [string]$UrlFile,
    [string]$LogDir,
    [string]$LockPath,
    [switch]$NoClipboard
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$HarnessDir = Join-Path $Root 'src\deepseek-harness'
if (-not $LogDir)  { $LogDir  = Join-Path $Root 'state' }
if (-not $UrlFile) { $UrlFile = Join-Path $Root 'state\superagent-url.txt' }
if (-not $LockPath) { $LockPath = Join-Path $Root 'state\superagent.lock' }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Anything in a fresh log that means the server is not (or no longer) healthy. "did not activate"
# is the line DSH prints when a plugin such as dsh-superagent fails its config validation.
$FailurePattern = 'startup failed|ELIFECYCLE|ValidationError|did not activate|EADDRINUSE|ERR_MODULE_NOT_FOUND'

function Get-Listeners([int]$LocalPort) {
    @(Get-NetTCPConnection -LocalPort $LocalPort -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique)
}

function Get-LockAge([string]$Path) {
    try { ((Get-Date) - (Get-Item -LiteralPath $Path -ErrorAction Stop).LastWriteTime).TotalSeconds } catch { $null }
}

function Get-CommandLine([int]$ProcessId) {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
    if ($p) { $p.CommandLine } else { $null }
}

# --- who holds the port? ----------------------------------------------------------------
$owners = @(Get-Listeners $Port)
foreach ($owner in $owners) {
    $proc = Get-Process -Id $owner -ErrorAction SilentlyContinue
    $name = if ($proc) { $proc.ProcessName } else { 'unknown' }
    $cmdline = Get-CommandLine $owner
    if (-not $cmdline) {
        Write-Host "port $Port is held by pid $owner ($name), but its command line cannot be read - it was probably started elevated. Run this script elevated." -ForegroundColor Yellow
        exit 2
    }
    if ($cmdline -notmatch $OwnerPattern) {
        Write-Host "port $Port is held by pid $owner ($name), which does not look like the superagent server (its command line does not match '$OwnerPattern'). Not stopping it." -ForegroundColor Red
        exit 2
    }
}

if ($DryRun) {
    if ($owners.Count) { Write-Host "would stop pid(s): $($owners -join ', ') (port $Port)" } else { Write-Host "port $Port is free - nothing to stop" }
    Write-Host "would run in ${HarnessDir}: $LaunchCommand   (DSH_HOME=$(Join-Path $Root '.dsh'), log in $LogDir)"
    exit 0
}

# --- stop the old server ----------------------------------------------------------------
foreach ($owner in $owners) {
    Write-Host "stopping pid $owner"
    try { Stop-Process -Id $owner -Force -ErrorAction Stop }
    catch {
        Write-Host "could not stop pid $owner : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'run this script from an elevated PowerShell' -ForegroundColor Yellow
        exit 2
    }
}
$freed = -not $owners.Count
for ($i = 0; (-not $freed) -and ($i -lt 40); $i++) {
    if (-not (Get-Listeners $Port).Count) { $freed = $true } else { Start-Sleep -Milliseconds 500 }
}
if (-not $freed) {
    Write-Host "port $Port is still in use 20 s after stopping its owner" -ForegroundColor Red
    exit 2
}

# The plugin guards its state directory with proper-lockfile, which treats a lock as stale only
# after 30 s without a heartbeat, and a force-stopped server cannot release its lock. A server
# launched sooner fails with "Lock file is already being held" and the plugin does not activate
# (this is what failed the 05:18 restart). So wait until the lock is gone or stale (cap: 45 s).
$lockWaitUntil = (Get-Date).AddSeconds(45)
$lockAge = Get-LockAge $LockPath
if (($null -ne $lockAge) -and ($lockAge -lt 32)) { Write-Host "waiting for the plugin lock to go stale (age $([int]$lockAge) s, needs 32 s): $LockPath" }
while (($null -ne $lockAge) -and ($lockAge -lt 32) -and ((Get-Date) -lt $lockWaitUntil)) {
    Start-Sleep -Seconds 2
    $lockAge = Get-LockAge $LockPath
}

# --- launch the new one -----------------------------------------------------------------
$env:DSH_HOME = Join-Path $Root '.dsh'
if (-not $env:DEEPSEEK_API_KEY) {
    $userKey = [Environment]::GetEnvironmentVariable('DEEPSEEK_API_KEY', 'User')
    if ($userKey) { $env:DEEPSEEK_API_KEY = $userKey }
}
$LogFile = Join-Path $LogDir ("superagent-restart-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Get-ChildItem $LogDir -Filter 'superagent-restart-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -Skip 5 |
    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }

# Launched through cmd so PowerShell's execution policy does not apply to pnpm.
$cmd = "cd /d `"$HarnessDir`" && $LaunchCommand > `"$LogFile`" 2>&1"
$launched = Start-Process cmd -ArgumentList '/c', $cmd -WindowStyle Hidden -PassThru

# --- wait for it, and do not believe the log alone --------------------------------------
$urlPattern = 'https?://127\.0\.0\.1:' + $Port + '/\?token=\S+'
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$url = $null
$failure = $null
$timedOut = $false
while ($true) {
    if ((Get-Date) -ge $deadline) { $timedOut = $true; $failure = "no verified URL within $TimeoutSeconds s"; break }
    Start-Sleep -Seconds 2
    $text = if (Test-Path $LogFile) { Get-Content $LogFile -Raw -ErrorAction SilentlyContinue } else { $null }
    if ($text -and ($text -match $FailurePattern)) { $failure = "the server logged: $($Matches[0])"; break }
    $listening = @(Get-Listeners $Port)
    if ($text -and ($text -match $urlPattern) -and $listening.Count) { $url = $Matches[0]; break }
    if ($launched.HasExited -and -not $listening.Count) { $failure = 'the server process exited before it started listening'; break }
}

if ($url) {
    # Settle check: a server that prints its URL and then dies is a failure.
    Start-Sleep -Seconds 8
    $textAfter = Get-Content $LogFile -Raw -ErrorAction SilentlyContinue
    $after = @(Get-Listeners $Port)
    if ($textAfter -and ($textAfter -match $FailurePattern)) {
        $failure = "the server logged: $($Matches[0]) after it printed its URL"
    } elseif (-not $after.Count) {
        $failure = "the server stopped listening on port $Port within 8 s of starting"
    } else {
        $now = Get-CommandLine $after[0]
        if ((-not $now) -or ($now -notmatch $OwnerPattern)) { $failure = "port $Port is now held by a process that is not the superagent server" }
    }
}

# --- report -----------------------------------------------------------------------------
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
if ($url -and -not $failure) {
    [IO.File]::WriteAllText($UrlFile, $url, $utf8NoBom)
    Write-Host ''
    Write-Host "superagent server is up on port $Port and still listening after the settle check. Open this URL (new token):" -ForegroundColor Green
    Write-Host "  $url" -ForegroundColor Cyan
    if (-not $NoClipboard) { Set-Clipboard -Value $url; Write-Host '(copied to clipboard)' }
    Write-Host "log: $LogFile"
    exit 0
}

[IO.File]::WriteAllText($UrlFile, 'no url captured', $utf8NoBom)
Write-Host "server did not come up: $failure" -ForegroundColor Red
$left = @(Get-Listeners $Port)
if ($left.Count) {
    Write-Host "NOTE: the server this script launched is still listening on port $Port (pid $($left -join ', ')) but is not healthy. Stop it (Stop-Process -Id $($left[0])) or fix the cause and run this script again." -ForegroundColor Yellow
}
if (Test-Path $LogFile) {
    Write-Host "last log lines ($LogFile):"
    Get-Content $LogFile -Tail 25 | ForEach-Object { $_ -replace 'token=[A-Za-z0-9_-]+', 'token=<redacted>' }
}
if ($timedOut) { exit 3 }
exit 1
