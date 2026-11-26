# Install (or remove) the logon trigger that opens everything at once.
#
# One task, three jobs, all idempotent - it runs deploy\dsh-autostart.ps1, which:
#   1. runs stack-up.ps1  -> Docker Desktop, both scanner stacks, the view proxy;
#   2. starts the web profile (:3080) if its port is closed;
#   3. starts the superagent profile (:3082) if its port is closed.
# Anything already listening is left untouched, so this is safe to re-run and
# safe to leave enabled while you work.
#
# A 30 s delay at logon is deliberate: Docker Desktop is itself a logon item, and
# two `docker` clients racing the engine's first start is how you get the flaky
# "cannot connect to the Docker daemon" window. stack-up.ps1 waits for the engine,
# so the delay simply avoids the contention rather than papering over it.
#
#   powershell -ExecutionPolicy Bypass -File deploy\install-dsh-autostart.ps1
#   powershell -ExecutionPolicy Bypass -File deploy\install-dsh-autostart.ps1 -Uninstall
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [int]$DelaySeconds = 30
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Script = Join-Path $Root 'deploy\dsh-autostart.ps1'
$TaskName = 'DSH Autostart'

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "Task '$TaskName' is not installed - nothing to remove."
    }
    exit 0
}

if (-not (Test-Path $Script)) { throw "Missing $Script" }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $Script)

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$trigger.Delay = ('PT{0}S' -f $DelaySeconds)

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Force `
    -Description ('Opens the whole local stack at logon: Docker, SecLayer/SecScan, view proxy, then the DSH web and superagent profiles. Idempotent - never restarts anything already listening.') | Out-Null

Write-Host "Registered '$TaskName' (at logon, +${DelaySeconds}s delay)."
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize | Out-String | Write-Host
Write-Host 'Log: .dsh\dsh-autostart.log  (profile output: .dsh\dsh-web.out.log, .dsh\dsh-superagent.out.log)'
