# Bring the whole local stack up at logon: Docker + scanners + view proxy, then
# the two DSH profiles - - and do nothing to anything that is already healthy.
#
# Order matters. stack-up.ps1 runs first because it is the only thing that can
# start Docker Desktop, wait for the engine and bring the containers and the
# view proxy up; it also takes its read-only path when everything answers, so
# running this against a live stack restarts nothing.
#
# The DSH profiles are then started only if their port is CLOSED. Liveness is a
# port test, not a URL test: both profiles answer 401 (Unauthorized) on / when
# they are perfectly healthy, so a URL probe would start a second copy against
# a port that is already bound.
#
#   powershell -ExecutionPolicy Bypass -File deploy\dsh-autostart.ps1
#
# Exit code 0 means "the stack is up": every step either succeeded or was
# already satisfied. Non-zero means at least one piece did not come up - the
# log says which.
[CmdletBinding()]
param(
    [int]$AppPort = 3080,
    [int]$SuperPort = 3082,
    [int]$WaitSeconds = 180
)

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$HarnessDir = Join-Path $Root 'src\deepseek-harness'
$LogFile = Join-Path $Root '.dsh\dsh-autostart.log'
$env:DSH_HOME = Join-Path $Root '.dsh'

function Write-Log($m) {
    $line = '{0:u} {1}' -f (Get-Date), $m
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
    Write-Host $line
}

function Test-Listener([int]$port) {
    return [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}

Write-Log '--- dsh-autostart start ---'

# 1. Docker Desktop + containers + view proxy. Idempotent, read-only if healthy.
$stackUp = Join-Path $Root 'deploy\stack-up.ps1'
if (Test-Path $stackUp) {
    if (Test-Listener 4710) {
        Write-Log 'scanners already listening on 4710 - running stack-up.ps1 (read-only fast path)'
    } else {
        Write-Log 'scanners not listening - running stack-up.ps1 to start Docker and the containers'
    }
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $stackUp *> $null
    Write-Log ("stack-up.ps1 returned exit code {0}" -f $LASTEXITCODE)
} else {
    Write-Log "WARN: $stackUp is missing - scanners were not started"
}

# 2. pnpm. A scheduled task inherits a different PATH than the interactive
#    shell, so resolve it explicitly instead of trusting the environment.
$pnpm = $null
foreach ($candidate in @(
        (Join-Path $env:APPDATA 'npm\pnpm.cmd'),
        (Join-Path $HarnessDir 'node_modules\.bin\pnpm.cmd'))) {
    if (Test-Path $candidate) { $pnpm = $candidate; break }
}
if (-not $pnpm) {
    $cmd = Get-Command pnpm.cmd -ErrorAction SilentlyContinue
    if ($cmd) { $pnpm = $cmd.Source }
}
if (-not $pnpm) { Write-Log 'ERROR: pnpm not found - DSH profiles were not started'; exit 1 }
if (-not (Test-Path (Join-Path $HarnessDir 'package.json'))) {
    Write-Log "ERROR: harness not found at $HarnessDir"; exit 1
}

# 3. Start each profile only if its port is closed, hidden, with output captured.
$profiles = @(
    @{ Name = 'web'; Port = $AppPort; Args = 'dsh web --no-open'; Log = 'dsh-web.out.log' },
    @{ Name = 'superagent'; Port = $SuperPort; Args = 'dsh --profile superagent --no-open'; Log = 'dsh-superagent.out.log' }
)

$started = @()
foreach ($p in $profiles) {
    if (Test-Listener $p.Port) {
        Write-Log ("{0} profile already listening on {1} - left alone" -f $p.Name, $p.Port)
        continue
    }
    Write-Log ("starting {0} profile on {1} ({2})" -f $p.Name, $p.Port, $p.Args)
    $outLog = Join-Path $Root ('.dsh\' + $p.Log)
    $cmdLine = 'cd /d "{0}" && "{1}" {2} >> "{3}" 2>&1' -f $HarnessDir, $pnpm, $p.Args, $outLog
    Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c ' + $cmdLine) -WindowStyle Hidden | Out-Null
    $started += $p
}

# 4. Wait for the ones we started, bounded, so the task's result is meaningful.
if ($started.Count -gt 0) {
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        $pending = @($started | Where-Object { -not (Test-Listener $_.Port) })
        if ($pending.Count -eq 0) { break }
        Start-Sleep -Seconds 3
    }
}

# 5. Report, and fail loudly if anything is still down.
$failed = @()
foreach ($p in $profiles) {
    if (Test-Listener $p.Port) { Write-Log ("OK   {0} listening on {1}" -f $p.Name, $p.Port) }
    else { Write-Log ("FAIL {0} not listening on {1}" -f $p.Name, $p.Port); $failed += $p.Name }
}
if (Test-Listener 4710 -and (Test-Listener 4711)) { Write-Log 'OK   scanners listening on 4710/4711' }
else { Write-Log 'FAIL scanners not listening on 4710/4711'; $failed += 'scanners' }

Write-Log ('--- dsh-autostart done, failures: ' + $(if ($failed.Count) { $failed -join ',' } else { 'none' }) + ' ---')
if ($failed.Count) { exit 1 } else { exit 0 }
