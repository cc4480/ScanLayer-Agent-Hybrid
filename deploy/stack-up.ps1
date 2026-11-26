# Ensure the whole local stack is up. Idempotent - safe to run any time.
#
#   powershell -ExecutionPolicy Bypass -File deploy\stack-up.ps1
#
# Docker Desktop is a desktop app, not a service: it does not come back when DSH
# restarts, only at Windows sign-in. Every container therefore disappears until
# someone starts it. This script makes that a one-step recovery, and the standing
# brief tells agents to run it in preflight.
[CmdletBinding()]
param(
    [int]$EngineTimeoutSeconds = 240
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$DockerBin = 'C:\Program Files\Docker\Docker\resources\bin'
$DockerExe = Join-Path $DockerBin 'docker.exe'
$DesktopExe = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'

function Say($m) { Write-Host $m }
function Have-Engine {
    if (-not (Test-Path $DockerExe)) { return $false }
    $null = & $DockerExe info --format '{{.ServerVersion}}' 2>$null
    return ($LASTEXITCODE -eq 0)
}

if (-not (Test-Path $DockerExe)) {
    throw "docker.exe not found at $DockerExe - is Docker Desktop installed?"
}

if (-not (Have-Engine)) {
    if (-not (Test-Path $DesktopExe)) { throw "Docker engine is down and Docker Desktop is not installed at $DesktopExe" }
    Say 'Docker engine is down - starting Docker Desktop...'
    Start-Process $DesktopExe | Out-Null
    $deadline = (Get-Date).AddSeconds($EngineTimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        if (Have-Engine) { break }
    }
    if (-not (Have-Engine)) { throw "Docker engine did not start within $EngineTimeoutSeconds s" }
}
Say ("Docker engine: " + (& $DockerExe info --format '{{.ServerVersion}}'))

# The view proxy is what the Browser panel embeds. The apps send
# X-Frame-Options: DENY and frame-ancestors 'none', so an iframe can never load
# them directly; the proxy serves the same app on 4710/4711 with only those two
# refusals removed. It is a host process, so it must be restarted after a reboot.
function Test-Port([int]$p) {
    return [bool](Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)
}
if (-not (Test-Port 4710) -or -not (Test-Port 4711)) {
    $nodeExe = (Get-Command node -ErrorAction SilentlyContinue).Source
    if ($nodeExe) {
        Say 'Starting the view proxy (4710 SecLayer, 4711 SecScan)...'
        Start-Process -FilePath $nodeExe -ArgumentList (Join-Path $Root 'deploy\view-proxy.mjs') `
            -WorkingDirectory $Root -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $Root '.dsh\view-proxy.log') `
            -RedirectStandardError (Join-Path $Root '.dsh\view-proxy.err.log')
        Start-Sleep -Seconds 2
    } else {
        Say 'WARN: node not found - the Browser panel proxy was not started.'
    }
}

# Read-only fast path. If everything is already healthy, touch nothing: a
# `compose up -d` on a live stack can recreate containers, and restarting a
# working scanner mid-use is worse than doing nothing.
function Test-Url($url) {
    try { $null = Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop; return $true }
    catch { return $false }
}
$healthyUrls = @(
    'http://127.0.0.1:4700/api/system/health',
    'http://127.0.0.1:4701/api/healthz'
)
$expected = @('seclayer', 'stack-db', 'vibescan-enterprise-build-web-1', 'vibescan-enterprise-build-secscan-1', 'vibescan-enterprise-build-db-1')
$running = @()
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$running = & $DockerExe ps --format '{{.Names}}' 2>$null
$ErrorActionPreference = $prevEap
$missing = $expected | Where-Object { $running -notcontains $_ }
$unhealthy = $healthyUrls | Where-Object { -not (Test-Url $_) }

if ($missing.Count -eq 0 -and $unhealthy.Count -eq 0) {
    Say 'Already up and healthy - nothing to do. Containers were not touched.'
    Say ''
    & $DockerExe ps --format '  {{.Names}}  {{.Status}}' 2>&1 | Where-Object { $_ -match '\S' }
    Say ''
    Say 'Health:'
    Say '  SecLayer  OK'
    Say '  SecScan   OK'
    exit 0
}
Say ("Recovery needed. Missing containers: " + $(if ($missing.Count) { $missing -join ', ' } else { 'none' }))
Say ("Unhealthy services: " + $(if ($unhealthy.Count) { ($unhealthy -join ', ') } else { 'none' }))


# Containers carry `restart: unless-stopped`, so they return by themselves once the
# engine is up. `compose up -d` here only matters when a project has never been
# started, or when a container was removed.
$projects = @(
    @{ Name = 'SecLayer'; Dir = 'C:\sh\src\seclayer.io2026'; Files = @('docker-compose.yml', (Join-Path $Root 'deploy\seclayer.ports.yml'), (Join-Path $Root 'deploy\seclayer.db.yml')) },
    @{ Name = 'SecScan';  Dir = 'C:\sh\src\VibeScan-Enterprise-Build'; Files = @('docker-compose.yml'); EnvFile = '.env.docker' }
)

foreach ($p in $projects) {
    if (-not (Test-Path (Join-Path $p.Dir 'docker-compose.yml'))) { Say ("$($p.Name): source not found at $($p.Dir) - skipped"); continue }
    Push-Location $p.Dir
    try {
        $composeArgs = @('compose')
        if ($p.EnvFile) { $composeArgs += @('--env-file', $p.EnvFile) }
        foreach ($f in $p.Files) { $composeArgs += @('-f', $f) }
        $composeArgs += @('up', '-d')
        # docker writes progress to stderr; under EAP=Stop that would throw.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $DockerExe @composeArgs *> $null
        $ErrorActionPreference = $prevEap
        Say ("$($p.Name): compose up -d done")
    } finally { Pop-Location }
}

Say ''
Say 'Containers:'
& $DockerExe ps --format '  {{.Names}}  {{.Status}}' 2>&1 | Where-Object { $_ -match '\S' }

Say ''
Say 'Health:'
$checks = @(
    @{ Name = 'SecLayer'; Url = 'http://127.0.0.1:4700/api/system/health' },
    @{ Name = 'SecScan';  Url = 'http://127.0.0.1:4701/api/healthz' }
)
$allOk = $true
foreach ($c in $checks) {
    $ok = $false; $detail = ''
    for ($i = 0; $i -lt 20; $i++) {
        try {
            $r = Invoke-WebRequest $c.Url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            $ok = $true; $detail = $r.Content; break
        } catch { Start-Sleep -Seconds 3 }
    }
    if (-not $ok) { $allOk = $false }
    Say ("  {0,-9} {1} {2}" -f $c.Name, $(if ($ok) { 'OK  ' } else { 'FAIL' }), $detail)
}

if (-not $allOk) {
    Say ''
    Say 'One or more apps are unhealthy. Container logs:'
    Say '  docker logs --tail 40 seclayer'
    Say '  docker logs --tail 40 vibescan-enterprise-build-web-1'
    exit 1
}
Say ''
Say 'Stack is up. MCP sections reconnect on their own.'
