# Keep the scanner stack tied to the app's lifetime.
#
# Docker Desktop is a desktop app: closing it (or signing out) stops the engine
# and every container with it. The scheduled stack-up task only checks every few
# minutes, which is too slow when you have just reopened the app and want to
# scan. This watcher closes that gap: while the DSH app is listening on its port
# it checks the two scanner health endpoints every couple of seconds and, the
# moment they are not answering, runs stack-up.ps1 - which starts Docker
# Desktop, waits for the engine, and brings the containers up.
#
# It is not edge-triggered on the app's start on purpose: the common case is the
# app still running while Docker Desktop was closed.
#
#   powershell -ExecutionPolicy Bypass -File deploy\stack-watch.ps1
[CmdletBinding()]
param(
    [int]$AppPort = 3080,
    [int]$PollSeconds = 2,
    [int]$MinGapSeconds = 20
)

$ErrorActionPreference = 'Stop'
$StackScript = Join-Path $PSScriptRoot 'stack-up.ps1'
$LogFile = Join-Path (Split-Path -Parent $PSScriptRoot) '.dsh\stack-watch.log'

function Write-Log($m) {
    $line = '{0:u} {1}' -f (Get-Date), $m
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

function Test-Listener([int]$port) {
    return [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}

function Test-Url($url) {
    try { $null = Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 4; return $true } catch { return $false }
}

Write-Log ('watcher started (app port ' + $AppPort + ', poll ' + $PollSeconds + 's)')
$lastRun = [datetime]::MinValue

while ($true) {
    try {
        if (Test-Listener $AppPort) {
            $healthy = (Test-Url 'http://127.0.0.1:4700/api/system/health') -and
                       (Test-Url 'http://127.0.0.1:4701/api/healthz')
            $gap = ((Get-Date) - $lastRun).TotalSeconds
            if (-not $healthy -and $gap -ge $MinGapSeconds) {
                $lastRun = Get-Date
                Write-Log 'scanners not answering - running stack-up.ps1'
                & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $StackScript *> $null
                Write-Log 'stack-up.ps1 returned'
            }

            # The view proxy is a separate host process; neither the containers nor
            # stack-up's container path revives it. If it is gone, the Browser panel
            # is blank even though both apps answer - so start it here too.
            if (-not (Test-Listener 4710) -or -not (Test-Listener 4711)) {
                $gap = ((Get-Date) - $lastRun).TotalSeconds
                if ($gap -ge $MinGapSeconds) {
                    $lastRun = Get-Date
                    $nodeExe = (Get-Command node -ErrorAction SilentlyContinue).Source
                    if ($nodeExe) {
                        Write-Log 'view proxy not listening - starting view-proxy.mjs'
                        $root = Split-Path -Parent $PSScriptRoot
                        Start-Process -FilePath $nodeExe `
                            -ArgumentList (Join-Path $PSScriptRoot 'view-proxy.mjs') `
                            -WorkingDirectory $root -WindowStyle Hidden `
                            -RedirectStandardOutput (Join-Path $root '.dsh\view-proxy.log') `
                            -RedirectStandardError (Join-Path $root '.dsh\view-proxy.err.log')
                        Start-Sleep -Seconds 2
                        Write-Log ('view proxy now listening: ' + ((Test-Listener 4710) -and (Test-Listener 4711)))
                    } else {
                        Write-Log 'WARN: node not found - view proxy not started'
                    }
                }
            }
        }
    } catch {
        Write-Log ('watcher error: ' + $_.Exception.Message)
    }
    Start-Sleep -Seconds $PollSeconds
}
