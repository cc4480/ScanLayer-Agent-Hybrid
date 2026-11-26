# Install (or remove) the trigger that brings the scanner stack back up.
#
# Why this exists: Docker Desktop is a desktop app, not a service. Closing its
# window - or signing out - stops the engine, and every container with it
# (seclayer, stack-db, the four vibescan-* ones). Nothing starts them again
# until someone runs stack-up.ps1 by hand. This registers one task that does it:
#
#   * at logon, so a reboot ends with the stack running;
#   * every 5 minutes, so reopening the app/window and getting the engine back
#     is enough - the task notices the engine is up and starts what is missing.
#
# stack-up.ps1 is idempotent and takes the read-only path when everything is
# already healthy: it does not restart a running scanner.
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
$TaskName = 'SecLayer Hybrid Stack'

if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) { Write-Host "No task named '$TaskName' is registered."; exit 0 }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'."
    exit 0
}

if (-not (Test-Path $StackScript)) { throw "stack-up.ps1 not found at $StackScript" }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $StackScript)

$atLogon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$repeating = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 20)

Register-ScheduledTask -TaskName $TaskName -Action $action `
    -Trigger @($atLogon, $repeating) -Settings $settings -Force `
    -Description 'Starts Docker Desktop and the SecLayer/SecScan containers when the machine or the app comes back. Idempotent: does nothing when the stack is already healthy.' | Out-Null

Write-Host "Registered '$TaskName' (at logon, and every $EveryMinutes min)."
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize | Out-String | Write-Host
