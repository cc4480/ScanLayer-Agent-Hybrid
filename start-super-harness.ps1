# Deepseek super - start script (Windows PowerShell)
#
# First run: installs dependencies, builds any missing artifacts, creates
# the superagent profile inside .dsh, links the superagent plugin, and
# writes its config. Later runs skip straight to launch (.setup-done flag).
#
# API key resolution (first hit wins):
#   1. The harness credential store:  .dsh\.credentials.yaml
#      (managed in the Web UI under Models; seated by Cho-zen1 - the
#       package intentionally ships without it)
#   2. DEEPSEEK_API_KEY from the Windows User environment variable
#   3. DEEPSEEK_API_KEY from a .env file in this folder
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$env:DSH_HOME = Join-Path $Root '.dsh'
New-Item -ItemType Directory -Force -Path $env:DSH_HOME | Out-Null
$StateDir = Join-Path $Root 'state\superagent'
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

# --- key routes 2 and 3 ------------------------------------------------------
if (-not $env:DEEPSEEK_API_KEY) {
    $userKey = [Environment]::GetEnvironmentVariable('DEEPSEEK_API_KEY', 'User')
    if ($userKey) { $env:DEEPSEEK_API_KEY = $userKey }
}
# .env supplies DEEPSEEK_API_KEY (if not already set) and DATABASE_URL (the scan engine's Postgres).
$envFile = Join-Path $Root '.env'
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if (-not $env:DEEPSEEK_API_KEY -and $line -match '^\s*DEEPSEEK_API_KEY\s*=\s*(.+?)\s*$') {
            $env:DEEPSEEK_API_KEY = $Matches[1]
        }
        if (-not $env:DATABASE_URL -and $line -match '^\s*DATABASE_URL\s*=\s*(.+?)\s*$') {
            $env:DATABASE_URL = $Matches[1]
        }
        if (-not $env:SCAN_SKIP_OWNERSHIP_GATE -and $line -match '^\s*SCAN_SKIP_OWNERSHIP_GATE\s*=\s*(.+?)\s*$') {
            $env:SCAN_SKIP_OWNERSHIP_GATE = $Matches[1]
        }
        # Engine-side overrides (VibeScan activeProbeGate.ts): let the deep tier run without a DB verification row.
        if (-not $env:ALLOW_UNVERIFIED_ACTIVE_PROBES -and $line -match '^\s*ALLOW_UNVERIFIED_ACTIVE_PROBES\s*=\s*(.+?)\s*$') {
            $env:ALLOW_UNVERIFIED_ACTIVE_PROBES = $Matches[1]
        }
        if (-not $env:DEV_SKIP_DOMAIN_VERIFICATION -and $line -match '^\s*DEV_SKIP_DOMAIN_VERIFICATION\s*=\s*(.+?)\s*$') {
            $env:DEV_SKIP_DOMAIN_VERIFICATION = $Matches[1]
        }
    }
}
# No NODE_OPTIONS here: the harness already starts under tsx (pnpm dsh = node --import tsx/esm), which
# loads the TypeScript scan engines. A global --import tsx would also apply to every node process the agent's
# shell starts, and those fail with "Cannot find package 'tsx'" outside this folder.
if (-not $env:DATABASE_URL) {
    Write-Host '[warn] DATABASE_URL is not set in .env - webapp_scan will fail until it points at a migrated Postgres database.'
}
if ($env:SCAN_SKIP_OWNERSHIP_GATE -eq 'true') {
    Write-Host '[warn] SCAN_SKIP_OWNERSHIP_GATE=true - the domain ownership gate is OFF. The scanner will run active'
    Write-Host '       probes against ANY target with no DNS verification. Use only on targets you are authorized to test.'
}

# --- first-run setup -----------------------------------------------------------
$setupDone = Join-Path $Root '.setup-done'
if (-not (Test-Path $setupDone)) {
    Write-Host '[setup] First run: installing the harness dependencies - needs internet, takes a few minutes...'
    Push-Location (Join-Path $Root 'src\deepseek-harness')
    pnpm install
    if (-not (Test-Path 'apps\web\dist')) {
        Write-Host '[setup] Building harness artifacts...'
        pnpm run build:artifacts
    }
    Pop-Location

    Write-Host '[setup] Installing and building the superagent prototype...'
    Push-Location (Join-Path $Root 'src\dsh-superagent-prototype')
    pnpm install
    pnpm run build
    Pop-Location

    Write-Host '[setup] Installing and building the QNX bundle (dsh-qnx)...'
    Push-Location (Join-Path $Root 'src\dsh-qnx')
    pnpm install
    pnpm run build
    Pop-Location

    Write-Host '[setup] Creating the superagent profile and linking the plugin...'
    Push-Location (Join-Path $Root 'src\deepseek-harness')
    pnpm dsh superagent --from-default-profile web --dump-config | Out-Null
    pnpm dsh plugin --profile superagent add "link:$(Join-Path $Root 'src\dsh-superagent-prototype')"
    pnpm dsh plugin --profile superagent add "link:$(Join-Path $Root 'src\dsh-qnx')"
    Pop-Location

    Write-Host '[setup] Installing the scan gate and linking it into the web and superagent profiles...'
    Push-Location (Join-Path $Root 'src\dsh-redteam-gate')
    npm install
    if ($env:DATABASE_URL) { npx tsx src/engines/vibescan-core/lib/db/src/migrate.ts }
    Pop-Location
    Push-Location (Join-Path $Root 'src\deepseek-harness')
    pnpm dsh plugin --profile superagent add "link:$(Join-Path $Root 'src\dsh-redteam-gate')"
    pnpm dsh plugin --profile web add "link:$(Join-Path $Root 'src\dsh-redteam-gate')"
    Pop-Location

    Write-Host '[setup] Writing the superagent profile config...'
    $patch = @"
# Superagent profile config for this package (written by start-super-harness.ps1).
- id: webserver
  config:
    host: 127.0.0.1
    port: 3082
- id: dsh-superagent
  config:
    stateDir: $StateDir
"@
    Set-Content -Path (Join-Path $env:DSH_HOME 'profiles\superagent\cordis.patch.yml') -Value $patch -Encoding UTF8

    Set-Content -Path $setupDone -Value 'done'
    Write-Host '[setup] Setup complete.'
}

# --- launch ---------------------------------------------------------------------
Write-Host 'Starting the DeepSeek Harness Web UI  - http://127.0.0.1:3080'
Write-Host 'Starting the Superagent profile       - http://127.0.0.1:3082'
Write-Host 'Each server window prints a tokenized URL - open THAT url in the browser.'
Write-Host 'Keep both server windows open while testing. Close them to stop.'
$HarnessDir = Join-Path $Root 'src\deepseek-harness'
Start-Process cmd -ArgumentList '/k', "cd /d `"$HarnessDir`" && pnpm dsh web --no-open" -WindowStyle Normal
Start-Process cmd -ArgumentList '/k', "cd /d `"$HarnessDir`" && pnpm dsh --profile superagent --no-open" -WindowStyle Normal
