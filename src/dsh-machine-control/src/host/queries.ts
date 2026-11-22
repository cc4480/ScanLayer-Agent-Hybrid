/** Read machine facts by running a PowerShell script and converting the JSON it writes with `ConvertTo-Json`. */
import type { Executor } from './exec.ts'
import type { Fact, PageId, PanelData, Table, TableRow } from '../types.ts'

/** A JSON object as a PowerShell script produced it. */
type JsonObject = Record<string, unknown>

/** A page that answers with one record holding named collections, or one array of rows. */
interface PageSource {
  /** Script text; its stdout is JSON. */
  readonly script: string
  /** Where each table's rows come from: a property of the record, or the record itself when it is an array. */
  readonly tables: ReadonlyArray<{ readonly title: string; readonly source: string | undefined; readonly spec: RowSpec }>
  /** Facts read from the record. */
  readonly facts: ReadonlyArray<readonly [label: string, read: (data: JsonObject) => unknown]>
}

/** One table's columns and cell readers. */
interface RowSpec {
  readonly columns: ReadonlyArray<string>
  readonly cell: (row: JsonObject) => TableRow
}

/** Convert one value to a display string. */
function text(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}

/** Convert a JSON array; PowerShell serializes a single element as the bare object. */
function list(value: unknown): JsonObject[] {
  const items = Array.isArray(value) ? value : value === null || value === undefined ? [] : [value]
  return items.filter((item): item is JsonObject => typeof item === 'object' && item !== null)
}

/** Parse the JSON body of a command's stdout, or undefined when there is none. */
function parse(stdout: string): unknown {
  const trimmed = stdout.trim()
  if (trimmed === '') return undefined
  const start = trimmed.search(/[[{]/u)
  if (start < 0) return undefined
  try {
    return JSON.parse(trimmed.slice(start)) as unknown
  } catch {
    return undefined
  }
}

/** Format a byte count as gigabytes with one decimal. */
function gigabytes(bytes: unknown): string {
  const value = typeof bytes === 'number' ? bytes : Number.NaN
  return Number.isFinite(value) ? `${(value / 1024 / 1024 / 1024).toFixed(1)} GB` : ''
}

/** Build one table, reporting how many rows the cap left out. */
function tableOf(title: string, spec: RowSpec, rows: JsonObject[], cap: number): Table | undefined {
  if (rows.length === 0) return undefined
  const kept = rows.slice(0, cap).map(spec.cell)
  return { title, columns: spec.columns, rows: kept, ...(rows.length > cap ? { truncated: rows.length - cap } : {}) }
}

/** Facts with empty values removed. */
function factsOf(data: JsonObject, spec: PageSource['facts']): Fact[] {
  return spec.flatMap(([label, read]) => {
    const value = text(read(data))
    return value === '' ? [] : [{ label, value }]
  })
}

const OVERVIEW: PageSource = {
  script: [
    '$os = Get-CimInstance Win32_OperatingSystem',
    '$cs = Get-CimInstance Win32_ComputerSystem',
    '$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1',
    '$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"',
    '[pscustomobject]@{',
    '  Host = $env:COMPUTERNAME; User = $env:USERNAME; Os = $os.Caption; Build = $os.Version;',
    '  LastBoot = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString("s") };',
    '  UptimeHours = if ($os.LastBootUpTime) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1) };',
    '  Manufacturer = $cs.Manufacturer; Model = $cs.Model; Cpu = $cpu.Name;',
    '  Cores = $cpu.NumberOfCores; Logical = $cpu.NumberOfLogicalProcessors; RamBytes = $cs.TotalPhysicalMemory;',
    '  ProcessCount = (Get-Process).Count;',
    '  Disks = @($disks | ForEach-Object { [pscustomobject]@{ Drive = $_.DeviceID; FreeGB = [math]::Round($_.FreeSpace/1GB,1); SizeGB = [math]::Round($_.Size/1GB,1) } })',
    '} | ConvertTo-Json -Compress -Depth 4',
  ].join('\n'),
  facts: [
    ['Host', data => data.Host],
    ['User', data => data.User],
    ['Operating system', data => data.Os],
    ['Build', data => data.Build],
    ['Manufacturer', data => data.Manufacturer],
    ['Model', data => data.Model],
    ['Processor', data => data.Cpu],
    ['Cores', data => `${text(data.Cores)} physical / ${text(data.Logical)} logical`],
    ['Memory', data => gigabytes(data.RamBytes)],
    ['Processes', data => data.ProcessCount],
    ['Last boot', data => data.LastBoot],
    ['Uptime (hours)', data => data.UptimeHours],
  ],
  tables: [{
    title: 'Fixed drives',
    source: 'Disks',
    spec: { columns: ['Drive', 'Free', 'Size'], cell: row => [text(row.Drive), `${text(row.FreeGB)} GB`, `${text(row.SizeGB)} GB`] },
  }],
}

const PAGES: Record<Exclude<PageId, 'overview'>, PageSource> = {
  processes: {
    script: 'Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 200 Id,ProcessName,@{n="MemoryMB";e={[math]::Round($_.WorkingSet64/1MB)}},@{n="CpuSeconds";e={if($_.CPU){[math]::Round($_.CPU)}}},@{n="Started";e={if($_.StartTime){$_.StartTime.ToString("s")}}} | ConvertTo-Json -Compress',
    facts: [],
    tables: [{ title: 'Processes by memory', source: undefined, spec: { columns: ['PID', 'Name', 'Memory (MB)', 'CPU (s)', 'Started'], cell: row => [text(row.Id), text(row.ProcessName), text(row.MemoryMB), text(row.CpuSeconds), text(row.Started)] } }],
  },
  services: {
    // Status and StartType are enums, which ConvertTo-Json writes as numbers; stringify them for the table.
    script: 'Get-Service | Sort-Object -Property @{Expression={[int]$_.Status};Descending=$true}, Name | Select-Object Name,@{n="Status";e={$_.Status.ToString()}},@{n="StartType";e={$_.StartType.ToString()}},DisplayName | ConvertTo-Json -Compress',
    facts: [],
    tables: [{ title: 'Services', source: undefined, spec: { columns: ['Name', 'Status', 'Start type', 'Display name'], cell: row => [text(row.Name), text(row.Status), text(row.StartType), text(row.DisplayName)] } }],
  },
  startup: {
    script: [
      '$items = @()',
      // Every registry row shares one long path; a short hive-and-kind label reads better and keeps the column narrow.
      '$shorten = { param($scope) if ($scope -like "HKLM*") { $hive = "HKLM" } elseif ($scope -like "HKCU*") { $hive = "HKCU" } else { return $scope }; if ($scope -like "*RunOnce*") { $kind = "RunOnce" } elseif ($scope -like "*Run*") { $kind = "Run" } else { $kind = ($scope -split "\\\\")[-1] }; "$hive $kind" }',
      '$roots = @("HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce","HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")',
      'foreach ($root in $roots) {',
      '  if (Test-Path $root) {',
      '    foreach ($name in (Get-Item $root).Property) { $items += [pscustomobject]@{ Scope = (& $shorten $root); Name = $name; Command = [string](Get-ItemPropertyValue -Path $root -Name $name) } }',
      '  }',
      '}',
      'Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | ForEach-Object { $items += [pscustomobject]@{ Scope = (& $shorten $_.Location); Name = $_.Name; Command = $_.Command } }',
      '$items | ConvertTo-Json -Compress',
    ].join('\n'),
    facts: [],
    tables: [{ title: 'Startup items', source: undefined, spec: { columns: ['Scope', 'Name', 'Command'], cell: row => [text(row.Scope), text(row.Name), text(row.Command)] } }],
  },
  network: {
    script: [
      '$adapters = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.NetAdapter.Status -eq "Up" } | ForEach-Object { [pscustomobject]@{ Name = $_.InterfaceAlias; Address = ($_.IPv4Address.IPAddress -join ", "); Gateway = ($_.IPv4DefaultGateway.NextHop -join ", "); Dns = ($_.DNSServer.ServerAddresses -join ", ") } }',
      '$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,OwningProcess,@{n="Process";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}',
      '[pscustomobject]@{ Adapters = @($adapters); Listeners = @($listeners) } | ConvertTo-Json -Compress -Depth 4',
    ].join('\n'),
    facts: [],
    tables: [
      { title: 'Network adapters', source: 'Adapters', spec: { columns: ['Adapter', 'IPv4 address', 'Gateway', 'DNS'], cell: row => [text(row.Name), text(row.Address), text(row.Gateway), text(row.Dns)] } },
      { title: 'Listening TCP ports', source: 'Listeners', spec: { columns: ['Address', 'Port', 'PID', 'Process'], cell: row => [text(row.LocalAddress), text(row.LocalPort), text(row.OwningProcess), text(row.Process)] } },
    ],
  },
  security: {
    script: [
      '$defender = $null; try { $defender = Get-MpComputerStatus -ErrorAction Stop } catch {}',
      '$firewall = @(); try { $firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Enabled = $(if ($_.Enabled) { "On" } else { "Off" }); Inbound = $_.DefaultInboundAction.ToString(); Outbound = $_.DefaultOutboundAction.ToString() } }) } catch {}',
      '$bitlocker = $null; try { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; $bitlocker = [pscustomobject]@{ ProtectionStatus = $bl.ProtectionStatus.ToString(); VolumeStatus = $bl.VolumeStatus.ToString(); EncryptionPercentage = $bl.EncryptionPercentage } } catch {}',
      '$secureBoot = $null; try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch {}',
      '$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
      '$os = Get-CimInstance Win32_OperatingSystem',
      '[pscustomobject]@{ Defender = $defender; Firewall = $firewall; BitLocker = $bitlocker; SecureBoot = $secureBoot; Elevation = $admin; Os = $os.Caption; Build = $os.Version } | ConvertTo-Json -Compress -Depth 4',
    ].join('\n'),
    facts: [
      ['Operating system', data => data.Os],
      ['Build', data => data.Build],
      ['Microsoft Defender', data => {
        const defender = typeof data.Defender === 'object' && data.Defender !== null ? data.Defender as JsonObject : undefined
        if (defender === undefined) return 'status unavailable'
        return defender.AntivirusEnabled === true || defender.RealTimeProtectionEnabled === true ? 'enabled' : 'disabled'
      }],
      ['BitLocker (system volume)', data => {
        const volume = list(data.BitLocker)[0]
        if (volume === undefined) return 'unavailable'
        return text(volume.ProtectionStatus)
      }],
      ['Secure Boot', data => data.SecureBoot === true ? 'enabled' : data.SecureBoot === false ? 'disabled' : 'unavailable'],
      ['Elevation', data => data.Elevation === true ? 'administrator' : 'standard user'],
    ],
    tables: [{ title: 'Firewall profiles', source: 'Firewall', spec: { columns: ['Profile', 'Enabled', 'Inbound default', 'Outbound default'], cell: row => [text(row.Name), text(row.Enabled), text(row.Inbound), text(row.Outbound)] } }],
  },
  packages: {
    script: [
      // The uninstall registry is the authoritative installed-application list and answers in well under a second; a package
      // manager's own inventory is left to the machine_packages tool, where a user asked for it.
      '$apps = @(Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*","HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*","HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher)',
      '$npm = if (Get-Command npm -ErrorAction SilentlyContinue) { ((& npm ls -g --depth=0 2>$null) | Out-String).Trim() } else { "" }',
      '[pscustomobject]@{ Apps = $apps; Npm = $npm } | ConvertTo-Json -Compress -Depth 4',
    ].join('\n'),
    facts: [
      ['Installed applications', data => `${String(list(data.Apps).length)} registered under Windows uninstall keys`],
      ['Global npm packages', data => {
        const shown = text(data.Npm)
        if (shown === '' || shown.includes('(empty)')) return 'none'
        return `${String(shown.split('\n').filter(line => line.includes('──')).length)} listed`
      }],
    ],
    tables: [{ title: 'Installed applications', source: 'Apps', spec: { columns: ['Name', 'Version', 'Publisher'], cell: row => [text(row.DisplayName), text(row.DisplayVersion), text(row.Publisher)] } }],
  },
  disk: {
    script: 'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { [pscustomobject]@{ Drive = $_.DeviceID; Label = $_.VolumeName; FileSystem = $_.FileSystem; SizeGB = [math]::Round($_.Size/1GB,1); FreeGB = [math]::Round($_.FreeSpace/1GB,1); UsedPercent = if ($_.Size) { [math]::Round(($_.Size - $_.FreeSpace) / $_.Size * 100) } else { 0 } } } | ConvertTo-Json -Compress',
    facts: [],
    tables: [{ title: 'Fixed drives', source: undefined, spec: { columns: ['Drive', 'Label', 'File system', 'Size (GB)', 'Free (GB)', 'Used %'], cell: row => [text(row.Drive), text(row.Label), text(row.FileSystem), text(row.SizeGB), text(row.FreeGB), text(row.UsedPercent)] } }],
  },
}

/**
 * Collect one page's data.
 * @param exec - the executor that runs the page script.
 * @param page - the page to collect.
 * @param cap - the largest number of rows kept per table.
 * @returns the facts and tables the panel renders.
 */
export async function collectPage(exec: Executor, page: PageId, cap: number): Promise<PanelData> {
  const source = page === 'overview' ? OVERVIEW : PAGES[page]
  const outcome = await exec.run({ command: source.script, timeoutMs: page === 'packages' ? 120_000 : 45_000 })
  const data = parse(outcome.stdout)
  const notes: string[] = []
  if (outcome.stderr.trim() !== '') notes.push(outcome.stderr.trim())
  if (typeof data !== 'object' || data === null) {
    notes.push('The query returned no data.')
    return { page, collectedAt: new Date().toISOString(), facts: [], tables: [], notes }
  }
  const rows = Array.isArray(data) ? list(data) : undefined
  const record = rows === undefined ? data as JsonObject : {}
  const tables = source.tables.flatMap((entry) => {
    const built = tableOf(entry.title, entry.spec, rows ?? list(record[entry.source ?? '']), cap)
    return built === undefined ? [] : [built]
  })
  return {
    page,
    collectedAt: new Date().toISOString(),
    facts: rows === undefined ? factsOf(record, source.facts) : [],
    tables,
    notes,
  }
}
