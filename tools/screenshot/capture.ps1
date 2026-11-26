<#
.SYNOPSIS
  Capture a window, the screen, or a rendered URL to a PNG the agent can read.

.DESCRIPTION
  -Mode window  : grab one top-level window (default: the DSH/Chrome window).
                  Tries PrintWindow (works while occluded), falls back to a
                  screen-region grab when the window paints black.
  -Mode screen  : grab the primary screen.
  -Mode url     : render a URL with headless Edge at -Width x -Height.

  Prints ONE line of JSON: {ok, mode, out, width, height, bytes, title, source}.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\screenshot\capture.ps1 -Mode window -Match "DSH Local Build"
  powershell -ExecutionPolicy Bypass -File tools\screenshot\capture.ps1 -Mode url -Url http://127.0.0.1:4710/r/shr_x -Height 3000
#>
[CmdletBinding()]
param(
    [ValidateSet('window', 'screen', 'url')]
    [string]$Mode = 'window',
    [string]$Match = '',
    [string]$Url = '',
    [string]$OutFile = '',
    [int]$Width = 1400,
    [int]$Height = 900,
    [int]$DelayMs = 350
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function New-OutPath([string]$tag) {
    if ($OutFile) { return $OutFile }
    $dir = Join-Path $env:TEMP 'dsh-shots'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return (Join-Path $dir ("{0}-{1}.png" -f $tag, (Get-Date -Format 'yyyyMMdd-HHmmss')))
}

if ($Mode -eq 'url') {
    if (-not $Url) { throw '-Mode url needs -Url' }
    $edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    if (-not (Test-Path $edge)) { $edge = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe' }
    if (-not (Test-Path $edge)) { throw 'Edge not found' }
    $out = New-OutPath 'url'
    $ud = Join-Path $env:TEMP ('shot-profile-' + [guid]::NewGuid().ToString('N'))
    $args = @(
        '--headless=new', '--disable-gpu', '--no-first-run', '--hide-scrollbars',
        '--virtual-time-budget=5000', ("--window-size=$Width,$Height"),
        ("--user-data-dir=$ud"), ("--screenshot=$out"), $Url
    )
    Start-Process -FilePath $edge -ArgumentList $args -Wait -WindowStyle Hidden
    Remove-Item -Recurse -Force $ud -ErrorAction SilentlyContinue
    if (-not (Test-Path $out)) { throw "no screenshot produced for $Url" }
    $img = [System.Drawing.Image]::FromFile($out)
    $res = @{ ok = $true; mode = 'url'; out = $out; width = $img.Width; height = $img.Height; bytes = (Get-Item $out).Length; title = $Url; source = 'headless-edge' }
    $img.Dispose()
    $res | ConvertTo-Json -Compress
    return
}

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

if (-not ('WinShot32' -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinShot32 {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    public const int SW_RESTORE = 9;
    public const uint PW_RENDERFULLCONTENT = 2;
}
"@
}
[void][WinShot32]::SetProcessDPIAware()

function Get-TargetWindow {
    if ($Match) {
        $p = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and ($_.MainWindowTitle -match $Match -or $_.ProcessName -match $Match) } |
             Sort-Object StartTime -Descending | Select-Object -First 1
        if (-not $p) { throw "no window matches '$Match'" }
        return $p
    }
    $fg = [WinShot32]::GetForegroundWindow()
    $p = Get-Process | Where-Object { $_.MainWindowHandle -eq $fg } | Select-Object -First 1
    if (-not $p) { throw 'no foreground window' }
    return $p
}

function Test-Alive([System.Drawing.Bitmap]$bmp) {
    $w = $bmp.Width; $h = $bmp.Height
    $stepX = [Math]::Max(1, [int]($w / 40)); $stepY = [Math]::Max(1, [int]($h / 40))
    $lit = 0; $seen = 0
    for ($x = 0; $x -lt $w; $x += $stepX) {
        for ($y = 0; $y -lt $h; $y += $stepY) {
            $seen++
            $c = $bmp.GetPixel($x, $y)
            if (($c.R + $c.G + $c.B) -gt 30) { $lit++ }
        }
    }
    return ($seen -gt 0 -and ($lit / $seen) -gt 0.02)
}

function Save-Bitmap([System.Drawing.Bitmap]$bmp, [string]$path) {
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
}

$source = ''; $title = ''
if ($Mode -eq 'screen') {
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bmp.Size)
    $g.Dispose()
    $title = 'primary screen'; $source = 'screen'
} else {
    $proc = Get-TargetWindow
    $hwnd = $proc.MainWindowHandle
    $title = $proc.MainWindowTitle
    if ([WinShot32]::IsIconic($hwnd)) { [void][WinShot32]::ShowWindow($hwnd, [WinShot32]::SW_RESTORE); Start-Sleep -Milliseconds 300 }
    $r = New-Object WinShot32+RECT
    if (-not [WinShot32]::GetWindowRect($hwnd, [ref]$r)) { throw 'GetWindowRect failed' }
    $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
    if ($w -le 0 -or $h -le 0) { throw "bad window rect ${w}x${h}" }

    # 1) PrintWindow: captures an occluded window, no focus steal
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [WinShot32]::PrintWindow($hwnd, $hdc, [WinShot32]::PW_RENDERFULLCONTENT)
    $g.ReleaseHdc($hdc); $g.Dispose()
    if ($ok -and (Test-Alive $bmp)) { $source = 'printwindow' }
    else {
        # 2) fall back to a screen-region grab with the window brought forward
        if ($bmp) { $bmp.Dispose() }
        [void][WinShot32]::SetForegroundWindow($hwnd)
        Start-Sleep -Milliseconds $DelayMs
        $bmp = New-Object System.Drawing.Bitmap($w, $h)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
        $g.Dispose()
        $source = 'screen-region'
    }
}

$out = New-OutPath $Mode
Save-Bitmap $bmp $out
$res = @{ ok = $true; mode = $Mode; out = $out; width = $bmp.Width; height = $bmp.Height; bytes = (Get-Item $out).Length; title = $title; source = $source }
$bmp.Dispose()
$res | ConvertTo-Json -Compress
