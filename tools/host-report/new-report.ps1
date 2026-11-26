# One command: scaffold a host report from the canonical template.
#
#   powershell -ExecutionPolicy Bypass -File tools\host-report\new-report.ps1 `
#       -HostName WORKSTATION-01 -Platform windows -Date 2026-11-26 `
#       -Os "Windows 11 Pro 24H2" -Build "10.0.26100" -Addresses "192.0.2.10 / 100.64.0.10" `
#       -Posture 62 -Medium 3 -Low 4 -Info 3 -Checks 65
#
# It copies skills/local-host-report/assets/template.html, substitutes identity and
# counters, writes reports/host-pentest-<HOST>-<DATE>.html, checks the markup, and
# renders a preview. It does NOT invent findings: fill sections 2/4/6-8/11 with real data.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HostName,
    [ValidateSet('windows', 'linux', 'ios')][string]$Platform = 'windows',
    [string]$Date = (Get-Date -Format 'yyyy-MM-dd'),
    [string]$Os = '',
    [string]$Build = '',
    [string]$Addresses = '',
    [string]$Window = '',
    [int]$Posture = 0,
    [int]$Critical = 0,
    [int]$High = 0,
    [int]$Medium = 0,
    [int]$Low = 0,
    [int]$Info = 0,
    [string]$Checks = '0',
    [string]$OutDir = '',
    [switch]$SkipRender
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$template = Join-Path $root 'skills\local-host-report\assets\template.html'
if (-not (Test-Path $template)) { throw "Template not found: $template" }
if (-not $OutDir) { $OutDir = Join-Path $root 'reports' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$labels = @{ windows = 'Windows'; linux = 'Linux'; ios = 'iOS' }
$defaults = @{
    windows = @{ os = 'Windows 11 Pro 24H2'; build = '10.0.26100' }
    linux   = @{ os = 'Ubuntu 24.04 LTS'; build = '6.8.0-generic' }
    ios     = @{ os = 'iOS 18'; build = '22A000' }
}
if (-not $Os) { $Os = $defaults[$Platform].os }
if (-not $Build) { $Build = $defaults[$Platform].build }
if (-not $Window) { $Window = "$Date host assessment" }

$t = [System.IO.File]::ReadAllText($template, [System.Text.Encoding]::UTF8)
$label = $labels[$Platform]

# identity
$t = $t -replace '<title>[^<]*</title>', ('<title>' + $label + ' Host Pentest &mdash; ' + $HostName + ' &mdash; ' + $Date + '</title>')
$t = $t -replace '<span class="grad">[^<]*</span>', ('<span class="grad">' + $HostName + '</span>')
$sub = $Os + ' &middot; build ' + $Build
if ($Addresses) { $sub = $sub + ' &middot; ' + $Addresses }
$t = $t -replace '<div class="sub">.*?</div>', ('<div class="sub">' + $sub + '</div>')
$t = $t -replace '<span class="chip"><b>Window</b>[^<]*</span>', ('<span class="chip"><b>Window</b> ' + $Window + '</span>')
$dot = [string][char]0x00B7
$t = $t -replace 'local host security report . windows', ('local host security report ' + $dot + ' ' + $Platform)

# counters
$pairs = @(
    @('Critical', $Critical), @('High', $High), @('Medium', $Medium), @('Low', $Low), @('Info', $Info)
)
foreach ($pair in $pairs) {
    $name = $pair[0]; $value = [string]$pair[1]
    $pat = '(<div class="card[^"]*"><div class="n pop"[^>]*>)\d+(</div><div class="l">' + $name + '</div>)'
    $t = [regex]::Replace($t, $pat, ('${1}' + $value + '${2}'))
}
$t = [regex]::Replace($t, '(--p:)\d+("><span>)\d+(</span>)', ('${1}' + $Posture + '${2}' + $Posture + '${3}'))

# summary line
$sevText = @()
if ($Critical) { $sevText += "$Critical Critical" }
if ($High) { $sevText += "$High High" }
if ($Medium) { $sevText += "$Medium Medium" }
if ($Low) { $sevText += "$Low Low" }
if ($Info) { $sevText += "$Info Info" }
$total = $Critical + $High + $Medium + $Low + $Info
$summary = "$total findings from $Checks checks"
if ($sevText.Count) { $summary = $summary + ': ' + ($sevText -join ', ') }
$summary = $summary + '. Every one carries its proof and a command that confirms the fix.'
$t = $t -replace '<p class="note" style="color:var\(--mut\)">Ten findings[^<]*</p>', ('<p class="note" style="color:var(--mut)">' + $summary + '</p>')

# footer
$t = $t.Replace('Generated 2026-11-26 from a read-only assessment of WORKSTATION-01.', ('Generated ' + $Date + ' from a read-only assessment of ' + $HostName + '.'))
$t = $t.Replace('"name":"WORKSTATION-01"', ('"name":"' + $HostName + '"'))
$t = $t.Replace('"os":"Microsoft Windows 10 Enterprise"', ('"os":"' + $Os + '"'))

# write
$out = Join-Path $OutDir ("host-pentest-" + $HostName + "-" + $Date + ".html")
[System.IO.File]::WriteAllText($out, $t, (New-Object System.Text.UTF8Encoding($false)))

# checks
$h = [System.IO.File]::ReadAllText($out, [System.Text.Encoding]::UTF8)
$problems = @()
foreach ($pair in @(@('<table', '</table>'), @('<details', '</details>'), @('<script', '</script>'))) {
    $open = ([regex]::Matches($h, [regex]::Escape($pair[0]))).Count
    $close = ([regex]::Matches($h, [regex]::Escape($pair[1]))).Count
    if ($open -ne $close) { $problems += ($pair[0] + ' ' + $open + ' vs ' + $pair[1] + ' ' + $close) }
}
$mojibake = ([string][char]0x00C2) + ([string][char]0x00B7)
if ($h.Contains($mojibake)) { $problems += 'mojibake detected' }
if (-not $h.TrimEnd().EndsWith('</html>')) { $problems += 'missing closing html tag' }

Write-Host ''
Write-Host ("report : " + $out)
Write-Host ("size   : " + ((Get-Item $out).Length) + " bytes")
if ($problems.Count) {
    Write-Host ("CHECK  : " + ($problems -join '; ')) -ForegroundColor Yellow
} else {
    Write-Host 'CHECK  : markup balanced, no mojibake' -ForegroundColor Green
}

# preview
if (-not $SkipRender) {
    $edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    if (-not (Test-Path $edge)) { $edge = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe' }
    if (Test-Path $edge) {
        $png = Join-Path $env:TEMP ("preview-" + [guid]::NewGuid().ToString('N') + ".png")
        $ud = Join-Path $env:TEMP ("edge-profile-" + [guid]::NewGuid().ToString('N'))
        $uri = 'file:///' + ($out -replace '\\', '/')
        Start-Process -FilePath $edge -ArgumentList @('--headless=new', '--disable-gpu', '--no-first-run', '--hide-scrollbars', '--virtual-time-budget=3000', '--window-size=1400,1600', ('--user-data-dir=' + $ud), ('--screenshot=' + $png), $uri) -Wait -WindowStyle Hidden
        if (Test-Path $png) { Write-Host ("preview: " + $png) }
        Remove-Item -Recurse -Force $ud -ErrorAction SilentlyContinue
    } else {
        Write-Host 'preview: skipped (Edge not found)'
    }
}

Write-Host ''
Write-Host 'NEXT (required):' -ForegroundColor Cyan
Write-Host '  1. fill sections 2 (findings), 4 (checks), 6-8 (evidence), 11 (data set) with real captures'
Write-Host '  2. keep the design: content changes, markup does not'
Write-Host '  3. add a row to reports/README.md'
Write-Host '  skills: web-scan-catalog (checks) + local-host-report (document)'
