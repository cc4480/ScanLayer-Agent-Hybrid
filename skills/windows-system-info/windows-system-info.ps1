<#
.SYNOPSIS
  Read-only Windows facts as ONE line of compact JSON: system, active window, idle time.

.DESCRIPTION
  -Info system  : OS, machine model, CPU, RAM, fixed-drive free space, uptime, user, PowerShell/Node versions
  -Info window  : foreground window title, process name/id, rectangle, minimized/maximized
  -Info idle    : seconds since the last keyboard/mouse input (Win32 GetLastInputInfo)
  -Info all     : all three (default)

  Works in Windows PowerShell 5.1 and PowerShell 7. The file is ASCII only on purpose.
  It only reads: no screenshots, no window contents, no process/window enumeration, nothing is written
  or changed. The only process-local side effect is that the helper process asks Windows to report real
  pixel coordinates (DPI awareness of this short-lived process); nothing outside the process changes.

  Source of truth: <project root>\skills\windows-system-info\ (versioned in git).
  Discovered copy: <project root>\.dsh\skills\windows-system-info\ (git-ignored). Sync with:
    Copy-Item -LiteralPath '<project root>\skills\windows-system-info' -Destination '<project root>\.dsh\skills' -Recurse -Force

.EXAMPLE
  & "C:\Users\Cho-zen\OneDrive\Desktop\Deepseek super\skills\windows-system-info\windows-system-info.ps1" -Info idle
#>
[CmdletBinding()]
param(
    [ValidateSet('system', 'window', 'idle', 'all')]
    [string]$Info = 'all'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Invariant culture so numbers and dates never use a decimal comma; restored in the finally block.
$script:SavedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
$script:Invariant = [System.Globalization.CultureInfo]::InvariantCulture
$script:Warnings = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------------------------
# Native helpers (user32). Compiled once per session; the type check makes a second run harmless.
# C# 5 syntax only, because Windows PowerShell 5.1 compiles with the .NET Framework csc.exe.
# ---------------------------------------------------------------------------------------------
$script:NativeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DshWinInfo
{
    public static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsZoomed(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowTextLengthW(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessDpiAwarenessContext(IntPtr value);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessDPIAware();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsProcessDPIAware();

        // Asks Windows to report real pixels for this (short-lived) process. Returns true when it is in effect.
        public static bool EnableDpiAwareness()
        {
            try { SetProcessDpiAwarenessContext(new IntPtr(-4)); } catch (Exception) { }
            try { if (!IsProcessDPIAware()) { SetProcessDPIAware(); } } catch (Exception) { }
            try { return IsProcessDPIAware(); } catch (Exception) { return false; }
        }

        public static uint GetProcessId(IntPtr hWnd)
        {
            uint pid = 0;
            GetWindowThreadProcessId(hWnd, out pid);
            return pid;
        }

        // { left, top, right, bottom } or null when the call fails.
        public static int[] GetRect(IntPtr hWnd)
        {
            RECT r;
            if (!GetWindowRect(hWnd, out r)) { return null; }
            return new int[] { r.Left, r.Top, r.Right, r.Bottom };
        }

        // Title bar text only (never window contents), capped at 512 characters.
        public static string GetTitle(IntPtr hWnd)
        {
            int len = GetWindowTextLengthW(hWnd);
            if (len <= 0) { return ""; }
            if (len > 512) { len = 512; }
            StringBuilder sb = new StringBuilder(len + 1);
            GetWindowTextW(hWnd, sb, sb.Capacity);
            return sb.ToString();
        }

        // Milliseconds since the last keyboard/mouse input of this session, or -1 when unavailable.
        // dwTime is a 32-bit tick count, so the subtraction is done in unsigned 32-bit arithmetic (wrap-safe).
        public static long GetIdleMilliseconds()
        {
            LASTINPUTINFO lii = new LASTINPUTINFO();
            lii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
            if (!GetLastInputInfo(ref lii)) { return -1; }
            uint now = unchecked((uint)Environment.TickCount);
            uint idle = unchecked(now - lii.dwTime);
            return (long)idle;
        }
    }
}
'@

function Initialize-Native {
    if ('DshWinInfo.Native' -as [type]) { return }
    Add-Type -TypeDefinition $script:NativeSource -ErrorAction Stop
}

# Runs a block; on failure records a warning and returns nothing (so the caller sees $null / empty).
function Invoke-Part {
    param([string]$Name, [scriptblock]$Block)
    try {
        return (& $Block)
    }
    catch {
        $script:Warnings.Add($Name + ': ' + $_.Exception.Message)
        return
    }
}

function Format-Iso {
    param([datetime]$When)
    return $When.ToString('yyyy-MM-ddTHH:mm:sszzz', $script:Invariant)
}

function Format-Duration {
    param([timespan]$Span)
    $parts = @()
    if ($Span.Days -gt 0) { $parts += ('{0}d' -f $Span.Days) }
    if ($Span.Days -gt 0 -or $Span.Hours -gt 0) { $parts += ('{0}h' -f $Span.Hours) }
    $parts += ('{0}m' -f $Span.Minutes)
    return ($parts -join ' ')
}

# ---------------------------------------------------------------------------------------------
# system_info
# ---------------------------------------------------------------------------------------------
function Get-SystemSection {
    # -Property keeps the WMI providers from computing expensive extras (Win32_Processor alone costs ~1 s without it).
    $os = Invoke-Part 'os' {
        Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory
    }
    $cs = Invoke-Part 'computer' {
        Get-CimInstance -ClassName Win32_ComputerSystem -Property Manufacturer, Model, UserName
    }

    $osInfo = Invoke-Part 'os' {
        if (-not $os) { throw 'Win32_OperatingSystem unavailable' }
        $cv =Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
        $revision = $null
        if ($cv -and $null -ne $cv.UBR) { $revision = [int]$cv.UBR }
        $displayVersion = $null
        if ($cv -and $cv.DisplayVersion) { $displayVersion = [string]$cv.DisplayVersion }
        [ordered]@{
            name            = ([string]$os.Caption).Trim()
            version         = [string]$os.Version
            build           = [int]$os.BuildNumber
            revision        = $revision
            display_version = $displayVersion
            architecture    = [string]$os.OSArchitecture
        }
    }

    $machine = Invoke-Part 'machine' {
        if (-not $cs) { throw 'Win32_ComputerSystem unavailable' }
        [ordered]@{
            computer_name = [string]$env:COMPUTERNAME
            manufacturer  = ([string]$cs.Manufacturer).Trim()
            model         = ([string]$cs.Model).Trim()
        }
    }

    $cpu = Invoke-Part 'cpu' {
        $cpus = @(Get-CimInstance -ClassName Win32_Processor -Property Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed)
        if ($cpus.Count -eq 0) { throw 'Win32_Processor unavailable' }
        $cores = 0
        $logical = 0
        foreach ($c in $cpus) {
            $cores += [int]$c.NumberOfCores
            $logical += [int]$c.NumberOfLogicalProcessors
        }
        [ordered]@{
            name               = (([string]$cpus[0].Name) -replace '\s+', ' ').Trim()
            sockets            = $cpus.Count
            cores              = $cores
            logical_processors = $logical
            max_mhz            = [int]$cpus[0].MaxClockSpeed
        }
    }

    $ram = Invoke-Part 'ram' {
        if (-not $os) { throw 'Win32_OperatingSystem unavailable' }
        $totalGb = [double]$os.TotalVisibleMemorySize / 1MB
        $freeGb = [double]$os.FreePhysicalMemory / 1MB
        $usedPct = 0.0
        if ($totalGb -gt 0) { $usedPct = 100.0 * ($totalGb - $freeGb) / $totalGb }
        [ordered]@{
            total_gb     = [math]::Round($totalGb, 2)
            free_gb      = [math]::Round($freeGb, 2)
            used_percent = [math]::Round($usedPct, 1)
        }
    }

    $disks = @(Invoke-Part 'disks' {
            foreach ($d in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -Property DeviceID, FileSystem, Size, FreeSpace)) {
                if ($null -eq $d.Size) { continue }
                $totalGb = [double]$d.Size / 1GB
                $freeGb = [double]$d.FreeSpace / 1GB
                $freePct = 0.0
                if ($totalGb -gt 0) { $freePct = 100.0 * $freeGb / $totalGb }
                [ordered]@{
                    drive        = [string]$d.DeviceID
                    file_system  = [string]$d.FileSystem
                    total_gb     = [math]::Round($totalGb, 1)
                    free_gb      = [math]::Round($freeGb, 1)
                    free_percent = [math]::Round($freePct, 1)
                }
            }
        })

    $uptime = Invoke-Part 'uptime' {
        if (-not $os) { throw 'Win32_OperatingSystem unavailable' }
        $boot = [datetime]$os.LastBootUpTime
        $span = (Get-Date) - $boot
        [ordered]@{
            seconds   = [int64][math]::Floor($span.TotalSeconds)
            text      = Format-Duration $span
            boot_time = Format-Iso $boot
        }
    }

    $userName = Invoke-Part 'user' {
        $u = [string]$cs.UserName
        if ([string]::IsNullOrWhiteSpace($u)) { $u = [string]$env:USERDOMAIN + '\' + [string]$env:USERNAME }
        $u
    }

    $shells = Invoke-Part 'powershell' {
        $pwshVersion = $null
        $pwshCmd = Get-Command -Name 'pwsh' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pwshCmd) {
            # The Store alias for pwsh.exe carries no file version, so fall back to the running version, then to asking pwsh.
            $pwshVersion = ([string](Get-Item -LiteralPath $pwshCmd.Source).VersionInfo.ProductVersion).Split(' ')[0]
            if ([string]::IsNullOrWhiteSpace($pwshVersion) -and $PSVersionTable.PSEdition -eq 'Core') {
                $pwshVersion = $PSVersionTable.PSVersion.ToString()
            }
            if ([string]::IsNullOrWhiteSpace($pwshVersion)) {
                $saved = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try { $pwshVersion = [string](& $pwshCmd.Source -NoProfile -NoLogo -Command '$PSVersionTable.PSVersion.ToString()' 2>$null | Select-Object -First 1) } finally { $ErrorActionPreference = $saved }
                if ([string]::IsNullOrWhiteSpace($pwshVersion)) { $pwshVersion = $null } else { $pwshVersion = $pwshVersion.Trim() }
            }
        }
        $winPs = $null
        $eng = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' -ErrorAction SilentlyContinue
        if ($eng -and $eng.PowerShellVersion) { $winPs = [string]$eng.PowerShellVersion }
        [ordered]@{
            running_edition    = [string]$PSVersionTable.PSEdition
            running_version    = $PSVersionTable.PSVersion.ToString()
            pwsh               = $pwshVersion
            windows_powershell = $winPs
        }
    }

    $nodeVersion = Invoke-Part 'node' {
        $v = $null
        $nodeCmd = Get-Command -Name 'node' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($nodeCmd) {
            $saved = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try { $v = (& $nodeCmd.Source --version 2>$null | Select-Object -First 1) } finally { $ErrorActionPreference = $saved }
            if ($v) { $v = ([string]$v).Trim().TrimStart('v') }
        }
        $v
    }

    return [ordered]@{
        os             = $osInfo
        machine        = $machine
        cpu            = $cpu
        ram            = $ram
        disks          = $disks
        uptime         = $uptime
        logged_on_user = $userName
        powershell     = $shells
        node           = $nodeVersion
    }
}

# ---------------------------------------------------------------------------------------------
# active_window
# ---------------------------------------------------------------------------------------------
function Get-WindowSection {
    Initialize-Native
    $dpiAware = [DshWinInfo.Native]::EnableDpiAwareness()

    $hwnd = [DshWinInfo.Native]::GetForegroundWindow()
    if ($hwnd.ToInt64() -eq 0) {
        return [ordered]@{
            available = $false
            reason    = 'no foreground window (screen locked, secure desktop, or focus is changing)'
        }
    }

    $procId = [int][DshWinInfo.Native]::GetProcessId($hwnd)
    $procName = $null
    try { $procName = [System.Diagnostics.Process]::GetProcessById($procId).ProcessName } catch { $procName = $null }

    $title = [DshWinInfo.Native]::GetTitle($hwnd)
    $minimized = [DshWinInfo.Native]::IsIconic($hwnd)
    $maximized = [DshWinInfo.Native]::IsZoomed($hwnd)
    $state = 'normal'
    if ($minimized) { $state = 'minimized' } elseif ($maximized) { $state = 'maximized' }

    $rect = $null
    $r = [DshWinInfo.Native]::GetRect($hwnd)
    if ($null -ne $r) {
        $rect = [ordered]@{
            left   = [int]$r[0]
            top    = [int]$r[1]
            right  = [int]$r[2]
            bottom = [int]$r[3]
            width  = [int]($r[2] - $r[0])
            height = [int]($r[3] - $r[1])
        }
    }

    $units = 'dpi_virtualized'
    if ($dpiAware) { $units = 'physical_pixels' }

    return [ordered]@{
        available    = $true
        title        = $title
        process_name = $procName
        process_id   = $procId
        state        = $state
        minimized    = [bool]$minimized
        maximized    = [bool]$maximized
        rect         = $rect
        rect_units   = $units
    }
}

# ---------------------------------------------------------------------------------------------
# idle_seconds
# ---------------------------------------------------------------------------------------------
function Get-IdleSection {
    Initialize-Native
    $ms = [DshWinInfo.Native]::GetIdleMilliseconds()
    if ($ms -lt 0) { throw 'GetLastInputInfo failed (no interactive session?)' }
    return [ordered]@{
        idle_seconds  = [math]::Round($ms / 1000.0, 1)
        idle_ms       = [int64]$ms
        last_input_at = Format-Iso ((Get-Date).AddMilliseconds(-$ms))
    }
}

# ---------------------------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------------------------
try {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:Invariant

    $result = [ordered]@{
        ok           = $true
        generated_at = Format-Iso (Get-Date)
    }
    if ($Info -eq 'system' -or $Info -eq 'all') { $result['system'] = Invoke-Part 'system' { Get-SystemSection } }
    if ($Info -eq 'window' -or $Info -eq 'all') { $result['window'] = Invoke-Part 'window' { Get-WindowSection } }
    if ($Info -eq 'idle' -or $Info -eq 'all') { $result['idle'] = Invoke-Part 'idle' { Get-IdleSection } }

    if ($script:Warnings.Count -gt 0) {
        $result['ok'] = $false
        $result['warnings'] = @($script:Warnings)
    }

    $json = $result | ConvertTo-Json -Compress -Depth 6
    # Keep stdout pure ASCII: escape every non-ASCII UTF-16 unit as \uXXXX, so titles in any script survive any console code page.
    $json = [regex]::Replace($json, '[^\x00-\x7F]', [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            return ('\u{0:x4}' -f [int][char]$m.Value)
        })
    Write-Output $json
}
finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:SavedCulture
}
