# One-command setup of the local SecLayer + SecScan stack on a fresh PC.
#
#   pwsh -File deploy/bootstrap.ps1
#
# Builds and starts both apps from their OWN docker-compose files, pins them to
# loopback ports 4700 / 4701, mints an API key from each app's own API, and
# writes the values DSH reads through ${credential:...}.
#
# Prerequisites: Docker Desktop running, and git. Nothing else.
# Idempotent: re-running rebuilds, restarts, and reuses the existing keys.
[CmdletBinding()]
param(
    [string]$SeclayerPort = '4700',
    [string]$SecscanPort  = '4701',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Seclayer = Join-Path $Root 'apps\seclayer'
$Secscan  = Join-Path $Root 'apps\secscan'
# DSH reads the project .env (gitignored) at startup, via ${credential:...}.
$EnvFile  = Join-Path $Root '.env'

function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "FAILED: $m" -ForegroundColor Red; exit 1 }

function Wait-Http($url, $seconds = 180) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { if ((Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { return $true } } catch { }
        Start-Sleep -Seconds 2
    }
    return $false
}

# --- prerequisites ------------------------------------------------------------
Step 'Checking prerequisites'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail 'docker is not installed. Install Docker Desktop, start it, and re-run.' }
try { docker info 2>$null | Out-Null } catch { Fail 'the Docker daemon is not running. Start Docker Desktop and re-run.' }
if (-not (Test-Path (Join-Path $Seclayer 'package.json'))) { Fail "SecLayer app missing at $Seclayer - run: git submodule update --init --recursive" }
if (-not (Test-Path (Join-Path $Secscan 'package.json')))  { Fail "SecScan app missing at $Secscan - run: git submodule update --init --recursive" }
'docker + both app checkouts present.'

# --- SecLayer ----------------------------------------------------------------
Step "SecLayer -> http://127.0.0.1:$SeclayerPort"
$seclayerEnv = Join-Path $Seclayer '.env'
if (-not (Test-Path $seclayerEnv)) {
    @(
        '# Written by deploy/bootstrap.ps1 - local single-operator instance.',
        'NODE_ENV=development',
        'APP_URL=http://127.0.0.1:' + $SeclayerPort,
        'DB_PATH=/data/seclayer.sqlite',
        '# Active probes need one of: a verified domain, or this operator switch.',
        '# Local single-operator box only; never set it on a deployment.',
        'ALLOW_UNVERIFIED_ACTIVE_PROBES=true'
    ) | Set-Content -Path $seclayerEnv -Encoding UTF8
    "wrote $seclayerEnv"
}
Push-Location $Seclayer
try {
    $composeArgs = @('compose', '-f', 'docker-compose.yml', '-f', (Join-Path $Root 'deploy\seclayer.ports.yml'), 'up', '-d')
    if (-not $SkipBuild) { $composeArgs += '--build' }
    & docker @composeArgs
    if ($LASTEXITCODE -ne 0) { Fail 'docker compose up failed for SecLayer (see output above)' }
} finally { Pop-Location }

if (-not (Wait-Http "http://127.0.0.1:$SeclayerPort/api/system/health")) {
    Push-Location $Seclayer; & docker compose logs --tail 30; Pop-Location
    Fail "SecLayer did not become healthy on $SeclayerPort"
}
'SecLayer healthy.'

# --- SecScan -----------------------------------------------------------------
Step "SecScan -> http://127.0.0.1:$SecscanPort"
$secscanEnvFile = Join-Path $Secscan '.env.docker'
if (-not (Test-Path $secscanEnvFile)) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $dbPass = [Convert]::ToBase64String($bytes) -replace '[^A-Za-z0-9]', ''
    $encKey = [Convert]::ToBase64String($bytes)
    @(
        '# Written by deploy/bootstrap.ps1 - local single-operator instance.',
        'POSTGRES_USER=vibescan',
        "POSTGRES_PASSWORD=$dbPass",
        'POSTGRES_DB=vibescan',
        "ENCRYPTION_KEY=$encKey",
        'APP_ORIGIN=http://127.0.0.1:' + $SecscanPort,
        "APP_PORT=$SecscanPort",
        'TRUST_PROXY=false'
    ) | Set-Content -Path $secscanEnvFile -Encoding UTF8
    "wrote $secscanEnvFile"
}
Push-Location $Secscan
try {
    & docker compose --env-file .env.docker --profile setup run --rm db-migrate
    if ($LASTEXITCODE -ne 0) { Fail 'SecScan database migration failed (see output above)' }
    $composeArgs = @('compose', '--env-file', '.env.docker', '-f', 'docker-compose.yml', '-f', (Join-Path $Root 'deploy\secscan.ports.yml'), 'up', '-d')
    if (-not $SkipBuild) { $composeArgs += '--build' }
    & docker @composeArgs
    if ($LASTEXITCODE -ne 0) { Fail 'docker compose up failed for SecScan (see output above)' }
} finally { Pop-Location }

if (-not (Wait-Http "http://127.0.0.1:$SecscanPort/api/health" 240)) {
    Write-Host 'SecScan did not answer /api/health - check the container logs before trusting the stack.' -ForegroundColor Yellow
}

# --- keys --------------------------------------------------------------------
Step 'Minting keys from each app (no live account involved)'
$seclayerKey = $null
try {
    $r = Invoke-RestMethod "http://127.0.0.1:$SeclayerPort/api/keys" -Method Post -ContentType 'application/json' -Body '{"name":"dsh-local"}' -TimeoutSec 30
    $seclayerKey = $r.rawKey
    'SecLayer key minted.'
} catch {
    Write-Host ("SecLayer key not minted automatically: " + $_.Exception.Message) -ForegroundColor Yellow
    Write-Host 'Open the app, sign in, and create one under Developer API Keys, then put it in .env.local.'
}

$existing = @{}
$otherLines = @()
if (Test-Path $EnvFile) {
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') {
            if ($Matches[1] -in @('SECLAYER_API_URL', 'SECLAYER_API_KEY', 'SECSCAN_API_URL', 'SECSCAN_API_TOKEN')) {
                $existing[$Matches[1]] = $Matches[2]
            } else {
                $otherLines += $line      # keep DEEPSEEK_API_KEY, DATABASE_URL, ...
            }
        } elseif ($line.Trim()) {
            $otherLines += $line
        }
    }
}
$out = [ordered]@{
    'SECLAYER_API_URL'  = "http://127.0.0.1:$SeclayerPort"
    'SECLAYER_API_KEY'  = $(if ($seclayerKey) { $seclayerKey } elseif ($existing['SECLAYER_API_KEY']) { $existing['SECLAYER_API_KEY'] } else { '' })
    'SECSCAN_API_URL'   = "http://127.0.0.1:$SecscanPort"
    'SECSCAN_API_TOKEN' = $(if ($existing['SECSCAN_API_TOKEN']) { $existing['SECSCAN_API_TOKEN'] } else { '' })
}
$lines = @($otherLines)
if ($lines.Count -gt 0) { $lines += '' }
$lines += '# Local stack (deploy/bootstrap.ps1). Keys are minted locally, never from the live services.'
foreach ($k in $out.Keys) { $lines += "$k=$($out[$k])" }
$lines | Set-Content -Path $EnvFile -Encoding UTF8
"merged local stack values into $EnvFile"

Step 'Done'
Write-Host "SecLayer : http://127.0.0.1:$SeclayerPort"
Write-Host "SecScan  : http://127.0.0.1:$SecscanPort"
if ($out['SECSCAN_API_TOKEN'] -eq '') {
    Write-Host 'SecScan token is empty: create one in the app (Settings -> API tokens) and add SECSCAN_API_TOKEN to .env.local.' -ForegroundColor Yellow
}
Write-Host 'Restart DSH so it re-reads .env.local.'
