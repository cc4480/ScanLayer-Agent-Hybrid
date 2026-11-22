/**
 * The one place a change command is written. Both the agent tools and the sidebar panels call these builders, so an
 * option in the UI runs exactly the PowerShell the model would run for the same operation.
 */

/** A value a builder splices into a PowerShell command. */
type Params = Record<string, unknown>

/** Quote a value as a single-quoted PowerShell string. */
export function quote(value: string): string {
  return `'${value.replaceAll("'", "''")}'`
}

/** Read a required non-empty string argument. */
export function str(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${name} must be a non-empty string.`)
  return value
}

/** Read an optional non-empty string argument. */
export function optionalStr(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined
}

/** Read a whole-number argument. */
export function int(value: unknown, name: string): number {
  const parsed = typeof value === 'number' ? value : Number(value)
  if (!Number.isInteger(parsed)) throw new Error(`${name} must be a whole number.`)
  return parsed
}

/**
 * Build the `-Id`/`-Name` switch that addresses one process. A name loses its `.exe` suffix, which `Get-Process` does not
 * accept. The selector is only built when an action needs it, so listing processes without a name works.
 * @param params - the tool or panel arguments, holding `id` or `name`.
 * @returns the PowerShell selector.
 */
export function processTarget(params: Params): string {
  if (params.id !== undefined && params.id !== null && params.id !== '') return `-Id ${String(int(params.id, 'id'))}`
  const name = str(params.name, 'name').replace(/\.exe$/iu, '')
  return `-Name ${quote(name)}`
}

/** Commands that read or change one process. */
export const processCommands = {
  list: (name?: string): string =>
    `Get-Process${name === undefined ? '' : ` -Name ${quote(name.replace(/\.exe$/iu, ''))}`} | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 50 Id,ProcessName,@{n="MemoryMB";e={[math]::Round($_.WorkingSet64/1MB)}},@{n="CpuSeconds";e={if($_.CPU){[math]::Round($_.CPU)}}} | Format-Table -AutoSize | Out-String`,
  start: (command: string): string =>
    `Start-Process ${quote(command)} -PassThru | Select-Object Id,ProcessName | Format-Table -AutoSize | Out-String`,
  stop: (target: string, force: boolean): string =>
    `Stop-Process ${target}${force ? ' -Force' : ''} -PassThru | Select-Object Id,ProcessName | Format-Table -AutoSize | Out-String`,
  restart: (target: string, force: boolean): string =>
    `$old = Get-Process ${target} -ErrorAction Stop; $path = $old.Path; if (-not $path) { throw 'The process has no executable path, so it cannot be restarted.' }; Stop-Process -InputObject $old${force ? ' -Force' : ''}; Start-Sleep -Milliseconds 700; Start-Process $path; 'restarted ' + $old.ProcessName`,
  details: (target: string): string =>
    `Get-Process ${target} | Select-Object Id,ProcessName,Path,@{n="Description";e={$_.Description}},@{n="Company";e={$_.Company}},StartTime,@{n="MemoryMB";e={[math]::Round($_.WorkingSet64/1MB)}},@{n="Threads";e={$_.Threads.Count}} | Format-List | Out-String`,
  suspend: (target: string): string =>
    `$p = Get-Process ${target} -ErrorAction Stop; Add-Type -Name Nat -Namespace Win32 -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);'; [Win32.Nat]::NtSuspendProcess($p.Handle) | Out-Null; 'suspended ' + $p.ProcessName`,
  resume: (target: string): string =>
    `$p = Get-Process ${target} -ErrorAction Stop; Add-Type -Name Nat -Namespace Win32 -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);'; [Win32.Nat]::NtResumeProcess($p.Handle) | Out-Null; 'resumed ' + $p.ProcessName`,
}

/** Commands that read or change one Windows service. */
export const serviceCommands = {
  list: (): string =>
    'Get-Service | Sort-Object Status,Name | Select-Object -First 200 Name,Status,StartType,DisplayName | Format-Table -AutoSize | Out-String',
  status: (name: string): string =>
    `Get-Service -Name ${quote(name)} -ErrorAction Stop | Format-List Name,Status,StartType,DisplayName | Out-String`,
  start: (name: string): string =>
    `Start-Service -Name ${quote(name)} -ErrorAction Stop; Get-Service -Name ${quote(name)} | Select-Object Name,Status | Format-Table -AutoSize | Out-String`,
  stop: (name: string): string =>
    `Stop-Service -Name ${quote(name)} -ErrorAction Stop; Get-Service -Name ${quote(name)} | Select-Object Name,Status | Format-Table -AutoSize | Out-String`,
  restart: (name: string): string =>
    `Restart-Service -Name ${quote(name)} -ErrorAction Stop; Get-Service -Name ${quote(name)} | Select-Object Name,Status | Format-Table -AutoSize | Out-String`,
  setStartup: (name: string, startup: 'automatic' | 'manual' | 'disabled'): string =>
    `Set-Service -Name ${quote(name)} -StartupType ${startup} -ErrorAction Stop; Get-Service -Name ${quote(name)} | Select-Object Name,Status,StartType | Format-Table -AutoSize | Out-String`,
}

/** Commands that read or reclaim disk space. */
export const diskCommands = {
  volumes: (): string =>
    'Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter,FileSystemLabel,FileSystem,HealthStatus,@{n="SizeGB";e={[math]::Round($_.Size/1GB,1)}},@{n="FreeGB";e={[math]::Round($_.SizeRemaining/1GB,1)}} | Format-Table -AutoSize | Out-String',
  /**
   * The largest folders and files under a directory.
   * @param path - the directory; the user profile when omitted. An omitted path is spliced as the live variable, not a
   * literal, so `$env:USERPROFILE` is expanded.
   *
   * A profile can hold hundreds of thousands of files, so the folder pass enumerates .NET-side (far faster than a
   * PowerShell pipeline per file), gives up after `$budget` seconds, and says how many folders it did not measure. The
   * answer is therefore always bounded, never a timeout.
   */
  usage: (path?: string): string => {
    const root = path === undefined ? '$env:USERPROFILE' : `(Resolve-Path -LiteralPath ${quote(path)} -ErrorAction Stop).Path`
    return [
      `$root = ${root}`,
      `if (-not (Test-Path -LiteralPath $root)) { throw ('No such directory: ' + $root) }`,
      `$budget = 40; $cap = 8`,
      `$total = [System.Diagnostics.Stopwatch]::StartNew()`,
      `$rows = @(); $skipped = 0; $cut = 0`,
      `foreach ($dir in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {`,
      `  if ($total.Elapsed.TotalSeconds -gt $budget) { $skipped++; continue }`,
      `  $sum = [long]0; $watch = [System.Diagnostics.Stopwatch]::StartNew(); $short = $false`,
      `  $stack = [System.Collections.Generic.Stack[string]]::new()`,
      `  $stack.Push($dir.FullName)`,
      `  while ($stack.Count -gt 0) {`,
      `    if ($watch.Elapsed.TotalSeconds -gt $cap) { $short = $true; break }`,
      `    $current = $stack.Pop()`,
      `    try {`,
      `      foreach ($file in [System.IO.Directory]::EnumerateFiles($current)) { $sum += ([System.IO.FileInfo]$file).Length }`,
      `      foreach ($sub in [System.IO.Directory]::EnumerateDirectories($current)) {`,
      `        if (([System.IO.File]::GetAttributes($sub) -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($sub) }`,
      `      }`,
      `    } catch { }`,
      `  }`,
      `  if ($short) { $cut++ }`,
      `  $rows += [pscustomobject]@{ Item = $dir.FullName; SizeGB = [math]::Round($sum/1GB,2) }`,
      `}`,
      `$rows | Sort-Object -Property SizeGB -Descending | Select-Object -First 15 | Format-Table -AutoSize -Wrap | Out-String`,
      `Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue | Sort-Object -Property Length -Descending | Select-Object -First 10 FullName,@{n="SizeMB";e={[math]::Round($_.Length/1MB,1)}} | Format-Table -AutoSize -Wrap | Out-String`,
      `if ($skipped -gt 0) { 'measurement stopped after ' + $budget + ' s; ' + $skipped + ' folders left unmeasured' }`,
      `if ($cut -gt 0) { $cut.ToString() + ' folder(s) were cut off at ' + $cap + ' s each, so their sizes are lower bounds' }`,
    ].join('\n')
  },
  cleanTemp: (drive: string): string => [
    `$before = (Get-PSDrive ${quote(drive)}).Free`,
    `Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue`,
    `$after = (Get-PSDrive ${quote(drive)}).Free`,
    `'freed ' + [math]::Round(($after - $before)/1MB,1) + ' MB from ' + $env:TEMP`,
  ].join('\n'),
  expand: (drive: string): string => [
    `$partition = Get-Partition -DriveLetter ${quote(drive)} -ErrorAction Stop`,
    `$supported = Get-PartitionSupportedSize -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -ErrorAction Stop`,
    `if ($supported.SizeMax -le $partition.Size) { 'no unallocated space next to ' + ${quote(drive)} } else { Resize-Partition -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -Size $supported.SizeMax -ErrorAction Stop; 'expanded ' + ${quote(drive)} + ' to ' + [math]::Round($supported.SizeMax/1GB,1) + ' GB' }`,
  ].join('\n'),
}

/** Commands that read or change the security posture. */
export const securityCommands = {
  /** Start a Defender scan. Windows exposes no supported way to cancel one, so there is no cancel command. */
  scanStart: (scan: 'quick' | 'full'): string =>
    `Start-MpScan -ScanType ${scan === 'full' ? 'FullScan' : 'QuickScan'} -ErrorAction Stop; "scan started: ${scan === 'full' ? 'full' : 'quick'}"`,
  scanStatus: (): string =>
    'Get-MpComputerStatus | Select-Object ScanParameters,QuickScanStartTime,QuickScanEndTime,FullScanStartTime,FullScanEndTime | Format-List | Out-String',
  upgrades: (): string => [
    'if (Get-Command winget -ErrorAction SilentlyContinue) { "winget:"; (& winget upgrade --include-unknown 2>$null) | Out-String }',
    'if (Get-Command scoop -ErrorAction SilentlyContinue) { "scoop:"; (& scoop status 2>$null) | Out-String }',
    'if (Get-Command npm -ErrorAction SilentlyContinue) { "npm:"; (& npm outdated -g 2>$null) | Out-String }',
  ].join('\n'),
}

/** Commands that change network state without an administrator. */
export const networkCommands = {
  clearDns: (): string => 'Clear-DnsClientCache; ipconfig /flushdns | Out-String',
}

/** One operation a panel button may run: its command, the parameters it reads, and whether it changes something. */
export interface PanelOperation {
  /** Human-readable name used in error messages and the audit log. */
  readonly title: string
  /** Whether the operation changes the machine, so the panel asks for confirmation. */
  readonly changes: boolean
  /** Build the PowerShell command from the request body. */
  readonly command: (params: Params) => string
}

/**
 * Operations the sidebar panels may run over HTTP. The list is closed: a request naming anything else is refused, so the
 * route can never turn into an arbitrary command runner.
 */
export const PANEL_OPERATIONS: Record<string, PanelOperation> = {
  'process.start': {
    title: 'Start a process',
    changes: true,
    command: params => processCommands.start(str(params.command, 'command')),
  },
  'process.stop': {
    title: 'End a process',
    changes: true,
    command: params => processCommands.stop(processTarget(params), params.force === true),
  },
  'process.restart': {
    title: 'Restart a process',
    changes: true,
    command: params => processCommands.restart(processTarget(params), params.force === true),
  },
  'service.start': {
    title: 'Start a service',
    changes: true,
    command: params => serviceCommands.start(str(params.name, 'name')),
  },
  'service.stop': {
    title: 'Stop a service',
    changes: true,
    command: params => serviceCommands.stop(str(params.name, 'name')),
  },
  'service.restart': {
    title: 'Restart a service',
    changes: true,
    command: params => serviceCommands.restart(str(params.name, 'name')),
  },
  'service.set-startup': {
    title: 'Change a service start type',
    changes: true,
    command: (params) => {
      const startup = str(params.startup, 'startup')
      if (startup !== 'automatic' && startup !== 'manual' && startup !== 'disabled') {
        throw new Error('startup must be automatic, manual or disabled.')
      }
      return serviceCommands.setStartup(str(params.name, 'name'), startup)
    },
  },
  'disk.clean-temp': {
    title: 'Delete temporary files',
    changes: true,
    command: params => diskCommands.cleanTemp((optionalStr(params.drive) ?? 'C').replace(/:$/u, '')),
  },
  'security.scan-start': {
    title: 'Start a Defender scan',
    changes: true,
    command: params => securityCommands.scanStart(params.scan === 'full' ? 'full' : 'quick'),
  },
  'network.clear-dns': {
    title: 'Clear the DNS cache',
    changes: true,
    command: () => networkCommands.clearDns(),
  },
}
