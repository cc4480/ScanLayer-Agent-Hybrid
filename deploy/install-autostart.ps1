# Install (or remove) the triggers that keep the scanner stack running.
#
# Docker Desktop is a desktop app, not a service: closing its window - or
# signing out - stops the engine and every container with it. Two tasks fix that:
#
#   SecLayer Stack Watch   at logon, runs the whole time the user is signed in.
#                          Checks the two scanner health endpoints every 2 s and,
#                          while the DSH app is listening, brings the stack back
#                          the moment it stops answering. This is the immediate
#                          path: close/reopen the app or Docker Desktop and the
#                          scanners are back within seconds, not minutes.
#
#   SecLayer Hybrid Stack  at logon and every 5 min, as a backstop for when the
#                          watcher is not running.
#
# Both run the existing idempotent stack-up.ps1, which takes its read-only path
# when everything is healthy and never restarts a working scanner.
#
#   powershell -ExecutionPolicy Bypass -File deploy\install-autostart.ps1
#   powershell -ExecutionPolicy Bypass -File deploy\install-autostart.ps1 -Uninstall
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [int]$EveryMinutes = 5
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$StackScript = Join-Path $Root 'deploy\stack-up.ps1'
$WatchScript = Join-Path $Root 'deploy\stack-watch.ps1'
$StackTask = 'SecLayer Hybrid Stack'
$WatchTask = 'SecLayer Stack Watch'

if ($Uninstall) {
    foreach ($n in @($WatchTask, $StackTask)) {
        if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $n -Confirm:$false
            Write-Host "Removed scheduled task '$n'."
        }
    }
    exit 0
}

foreach ($p in @($StackScript, $WatchScript)) {
    if (-not (Test-Path $p)) { throw "Missing $p" }
}

$stackAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $StackScript)
$atLogon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$repeating = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$stackSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 20)

Register-ScheduledTask -TaskName $StackTask -Action $stackAction `
    -Trigger @($atLogon, $repeating) -Settings $stackSettings -Force `
    -Description 'Starts Docker Desktop and the SecLayer/SecScan containers at logon and every few minutes. Idempotent.' | Out-Null

$watchAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $WatchScript)
$watchSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $WatchTask -Action $watchAction `
    -Trigger $atLogon -Settings $watchSettings -Force `
    -Description 'Keeps the scanner stack tied to the app: restores it within seconds of Docker Desktop or the app going away.' | Out-Null

Write-Host "Registered '$WatchTask' (continuous) and '$StackTask' (logon + every $EveryMinutes min)."
Get-ScheduledTask -TaskName $WatchTask, $StackTask | Select-Object TaskName, State | Format-Table -AutoSize | Out-String | Write-Host
