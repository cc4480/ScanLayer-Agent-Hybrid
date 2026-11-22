/**
 * The agent tools this bundle contributes: one tool per administration area over the same executor and queries the panels
 * use, so a command or change is reachable from the UI and from the model.
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { ToolOutputDefinition, ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { Executor } from './exec.ts'
import { collectPage } from './queries.ts'
import { renderPanel } from './render.ts'
import type { PageId } from '../types.ts'

/** Limits the tools enforce on model requests. */
export interface ToolLimits {
  readonly timeoutMs: number
  readonly maxTimeoutMs: number
  readonly maxOutputChars: number
  readonly rowCap: number
  /** Whether the command tools may include the machine catalog in the prompt. */
  readonly guide: boolean
}

/**
 * A command line plus the reason it needs elevation: `required` names an operation that needs an administrator, and
 * `isElevated` reports whether this process already has one to spend.
 */
interface ElevatedCommand {
  readonly command: string
  readonly required: string
  readonly isElevated: () => Promise<boolean>
}

/** The values a tool call replaces in a command template. */
type Values = Record<string, string>

/** Refuse a value that cannot be spliced into PowerShell as a single-quoted string. */
function quote(value: string): string {
  return `'${value.replaceAll("'", "''")}'`
}

/** A whole number argument. */
function integer(value: unknown, name: string): number {
  const parsed = typeof value === 'number' ? value : Number(value)
  if (!Number.isInteger(parsed)) throw new Error(`${name} must be a whole number.`)
  return parsed
}

/** A string argument. */
function string(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${name} must be a non-empty string.`)
  return value
}

/** Every answer the executor returns for a tool, trimmed to the model's output budget. */
interface CommandReport {
  readonly exitCode: number | null
  readonly stdout: string
  readonly stderr: string
  readonly truncated: boolean
}

function report(outcome: { exitCode: number | null; stdout: string; stderr: string }, maxChars: number): CommandReport {
  const combined = outcome.stdout.length + outcome.stderr.length
  const trim = (value: string): string => value.length <= maxChars ? value : value.slice(0, maxChars)
  return { exitCode: outcome.exitCode, stdout: trim(outcome.stdout), stderr: trim(outcome.stderr), truncated: combined > maxChars * 2 }
}

/** Format a command report for the model. */
function render(report: CommandReport): string {
  const lines = [`exit code: ${report.exitCode === null ? 'none' : String(report.exitCode)}`]
  if (report.stdout.trim() !== '') lines.push(report.stdout.trimEnd())
  if (report.stderr.trim() !== '') lines.push(`stderr:\n${report.stderr.trimEnd()}`)
  if (report.truncated) lines.push('[output truncated]')
  return lines.join('\n')
}

/** The machine catalog section added to the system prompt; it is fixed text from this plugin. */
const GUIDE = [
  '## Local machine administration',
  '',
  'This machine runs Windows. These tools act on it directly; prefer them over guessing at commands:',
  '',
  '- machine_shell: run a PowerShell command line. Elevation is spent once per call, so chain elevated work in one call.',
  '- machine_sysinfo: host, operating system, processor, memory, uptime and drives as text tables. area reads another panel:',
  '  processes, services, startup, network, security, packages, disk.',
  '- machine_process: action list, start, stop, restart, details, suspend or resume. A stopped or suspended change ends at reboot.',
  '- machine_service: action list, status, start, stop, restart, or set-startup (automatic, manual, disabled). Elevation is required.',
  '- machine_scheduled-task: action list, create, delete, run, enable, disable, or set (change the task\'s command).',
  '- machine_network: action adapters, ports, routes, dns, connections, ping, test (port reachability), or firewall-list. Only',
  '  firewall-add and firewall-remove change anything, and both require elevation; never open a port unless the user asked.',
  '- machine_security: action status, firewall, defender (real-time protection), update-check, audit-policy, the list of',
  '  installed security programs, winget/scoop/npm upgrade availability, or scan-start (needs a persistable plan to outlive the',
  '  request), scan-cancel and scan-status. Report what changed.',
  '- machine_packages: action search, list, install, uninstall, upgrade or source. winget, scoop and npm are supported; an',
  '  install or uninstall needs elevation when the package manager asks for it.',
  '- machine_disk: action volumes, usage (largest directories or files), clean-temp (deletes temporary files), or expand',
  '  (needs the unallocated space to be adjacent and the disk to be basic).',
  '- machine_maintenance: action reboot, shutdown, logoff, restart-explorer, clear-dns, flush-network, windows-update-list, or',
  '  windows-update-install. Reboot and shutdown end the session: confirm the user agreed before calling them.',
  '- machine_event-logs: list the newest events of one named log (System, Application, Security, Setup, ...) with filters.',
  '',
  'The Quit control keeps a plan file at %LOCALAPPDATA%\\dsh-machine-control-quit.json. Writing that JSON there, with kind',
  'set to `reboot`, `shutdown`, `reboot-update`, `explorer` or `flush-dns`, makes the control perform that action after a normal',
  'quit; the name can be a chosen date, time, restart or shutdown.',
].join('\n')

/** Tool schema definitions shared by both tools that take a command. */
const COMMAND_PARAMETERS = {
  type: 'object',
  properties: {
    command: { type: 'string', description: 'PowerShell command line to run on the machine.' },
    workdir: { type: 'string', description: 'Working directory; the machine default when omitted.' },
    timeoutMs: { type: 'integer', description: 'Deadline in milliseconds, capped by the plugin configuration.' },
    elevate: { type: 'boolean', description: 'Run the command with administrator rights through a UAC prompt the user must accept.' },
  },
  required: ['command'],
  additionalProperties: false,
}

const AREA_PARAMETERS = {
  type: 'object',
  properties: {
    area: {
      type: 'string',
      enum: ['processes', 'services', 'startup', 'network', 'security', 'packages', 'disk'],
      description: 'Panel area to read.',
    },
  },
  required: ['area'],
  additionalProperties: false,
}

/** Run a command that may need elevation and return the model-facing report. */

/**
 * Elevate one command: ask the user through the approval service, then run it through `Start-Process -Verb RunAs`.
 * The elevated process runs detached and writes its output to a temporary file, which is read back once it ends.
 * @param ctx - the plugin context, which provides the approval service and the active agents.
 * @param input - the command and the operation it needs elevation for.
 * @param agent - the agent whose turn the approval belongs to.
 * @param tool - the tool name the approval is reported under.
 * @returns the command line that runs the elevated copy and folds its output back in.
 * @throws when the user does not approve the request.
 */
async function elevate(ctx: Context, input: ElevatedCommand, agent: Agent | undefined, tool: string): Promise<string> {
  const approval = ctx.get('approval')
  const requester = agent ?? ctx.get('agents')?.list()[0]
  if (approval !== undefined && requester !== undefined) {
    const outcome = await approval.request({
      agent: requester,
      toolName: tool,
      reason: `${input.required}\n\nThe command runs in a UAC prompt you must accept.`,
    })
    if (outcome !== 'allowed-once') throw new Error('Elevation was not approved, so nothing ran.')
  }
  const out = `${process.env.TEMP ?? '.'}\\dsh-machine-control-${String(Date.now())}.log`
  return [
    `$log = ${quote(out)}`,
    `$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(${quote(input.command)}))`,
    `try {`,
    `  $process = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -Verb RunAs -Wait -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err" -WindowStyle Hidden`,
    `  Get-Content $log -Raw -ErrorAction SilentlyContinue`,
    `  $errors = Get-Content "$log.err" -Raw -ErrorAction SilentlyContinue`,
    `  if ($errors) { [Console]::Error.Write($errors) }`,
    `  Remove-Item $log, "$log.err" -ErrorAction SilentlyContinue`,
    `  exit $process.ExitCode`,
    `} catch { Write-Error ('Elevation failed: ' + $_.Exception.Message); exit 1 }`,
  ].join('\n')
}

/**
 * Register the tool set.
 * @param ctx - the plugin context.
 * @param executor - the command executor; a tool's own `exec` parameter is named `run` so it never shadows it.
 * @param limits - the configured limits.
 * @returns one disposer per registered tool.
 */
export function registerTools(ctx: Context, executor: Executor, limits: ToolLimits): Array<() => void> {
  const textOutput: ToolOutputDefinition = { schema: { type: 'string' }, render: (_args: unknown, value: unknown) => [{ type: 'text', text: String(value) }] }

  const tools = [
    {
      name: 'machine_shell',
      description: 'Run a PowerShell command line on this machine and return its exit code and output. Set elevate to run it with administrator rights; the user must accept a UAC prompt.',
      parameters: COMMAND_PARAMETERS,
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = typeof args === 'object' && args !== null ? args as Values & { elevate?: unknown; timeoutMs?: unknown } : {}
        const command = string(input.command, 'command')
        const timeoutMs = input.timeoutMs === undefined ? limits.timeoutMs : Math.min(integer(input.timeoutMs, 'timeoutMs'), limits.maxTimeoutMs)
        const elevated = input.elevate === true
        const line = elevated ? await elevate(ctx, { command, required: 'The model asked to run a command as administrator.', isElevated: async () => true }, run.agent, 'machine_shell') : command
        const outcome = await executor.run({ command: line, workdir: typeof input.workdir === 'string' ? input.workdir : undefined, timeoutMs })
        return render(report(outcome, limits.maxOutputChars))
      },
    },
    {
      name: 'machine_sysinfo',
      description: 'Read this machine: host, operating system, processor, memory, uptime, drives and process count. With area, read one panel area instead: processes, services, startup, network, security, packages or disk.',
      parameters: AREA_PARAMETERS,
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = typeof args === 'object' && args !== null ? args as { area?: unknown } : {}
        const area = input.area === undefined ? 'overview' : input.area
        const page = (['processes', 'services', 'startup', 'network', 'security', 'packages', 'disk'] as const).find(candidate => candidate === area) ?? 'overview'
        return renderPanel(await collectPage(executor, page satisfies PageId, limits.rowCap))
      },
    },
    {
      name: 'machine_process',
      description: 'Inspect or control a process by name or PID: action list, start, stop, restart, details, suspend or resume. stop and suspend without force may require administrator rights.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'start', 'stop', 'restart', 'details', 'suspend', 'resume'] },
          name: { type: 'string', description: 'Process name, with or without .exe.' },
          id: { type: 'integer', description: 'Process id; wins over name when both are given.' },
          command: { type: 'string', description: 'For start: the executable or command line, quoted as before.' },
          force: { type: 'boolean', description: 'For stop: kill immediately instead of asking the process to close.' },
          elevate: { type: 'boolean', description: 'Run the change as administrator through a UAC prompt.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        const action = string(input.action, 'action')
        const force = input.force === true ? ' -Force' : ''
        const target = input.id !== undefined ? `-Id ${String(integer(input.id, 'id'))}` : `-Name ${quote(string(input.name, 'name').replace(/\.exe$/iu, ''))}`
        const scripts: Record<string, string> = {
          list: `Get-Process${input.name === undefined ? '' : ` -Name ${quote(string(input.name, 'name').replace(/\.exe$/iu, ''))}`} | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 50 Id,ProcessName,@{n="MemoryMB";e={[math]::Round($_.WorkingSet64/1MB)}},@{n="CpuSeconds";e={if($_.CPU){[math]::Round($_.CPU)}}} | Format-Table -AutoSize | Out-String`,
          start: `Start-Process ${quote(string(input.command, 'command'))} -PassThru | Select-Object Id,ProcessName | Format-Table -AutoSize | Out-String`,
          stop: `Stop-Process ${target}${force} -PassThru | Select-Object Id,ProcessName | Format-Table -AutoSize | Out-String`,
          restart: `$old = Get-Process ${target} -ErrorAction Stop; $path = $old.Path; Stop-Process -InputObject $old${force}; Start-Sleep -Milliseconds 700; Start-Process $path; 'restarted ' + $old.ProcessName`,
          details: `Get-Process ${target} | Select-Object Id,ProcessName,Path,@{n="Description";e={$_.Description}},@{n="Company";e={$_.Company}},StartTime,@{n="MemoryMB";e={[math]::Round($_.WorkingSet64/1MB)}},@{n="Threads";e={$_.Threads.Count}} | Format-List | Out-String`,
          suspend: `$p = Get-Process ${target} -ErrorAction Stop; Add-Type -Name Nat -Namespace Win32 -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);'; [Win32.Nat]::NtSuspendProcess($p.Handle) | Out-Null; 'suspended ' + $p.ProcessName`,
          resume: `$p = Get-Process ${target} -ErrorAction Stop; Add-Type -Name Nat -Namespace Win32 -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);'; [Win32.Nat]::NtResumeProcess($p.Handle) | Out-Null; 'resumed ' + $p.ProcessName`,
        }
        const command = scripts[action]
        if (command === undefined) throw new Error(`Unknown action: ${action}`)
        const elevated = action !== 'list' && action !== 'details' && input.elevate === true
          ? await elevate(ctx, { command, required: `${action} with administrator rights`, isElevated: async () => true }, run.agent, 'machine_process')
          : command
        return render(report(await executor.run({ command: elevated, timeoutMs: limits.timeoutMs }), limits.maxOutputChars))
      },
    },
    {
      name: 'machine_service',
      description: 'Read or change a Windows service: action list, status, start, stop, restart, or set-startup. Changes need administrator rights.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'status', 'start', 'stop', 'restart', 'set-startup'] },
          name: { type: 'string', description: 'Service name or display name.' },
          startup: { type: 'string', enum: ['automatic', 'manual', 'disabled'], description: 'For set-startup.' },
          elevate: { type: 'boolean', description: 'Run the change as administrator through a UAC prompt.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        const action = string(input.action, 'action')
        const name = input.name === undefined ? undefined : string(input.name, 'name')
        const scripts: Record<string, string> = {
          list: 'Get-Service | Sort-Object Status,Name | Select-Object -First 200 Name,Status,StartType,DisplayName | Format-Table -AutoSize | Out-String',
          status: `Get-Service -Name ${quote(name ?? '')} -ErrorAction Stop | Format-List Name,Status,StartType,DisplayName | Out-String`,
          start: `Start-Service -Name ${quote(name ?? '')} -ErrorAction Stop; Get-Service -Name ${quote(name ?? '')} | Select-Object Name,Status | Format-Table -AutoSize | Out-String`,
          stop: `Stop-Service -Name ${quote(name ?? '')} -ErrorAction Stop; Get-Service -Name ${quote(name ?? '')} | Select-Object Name,Status | Format-Table -AutoSize | Out-String`,
          restart: `Restart-Service -Name ${quote(name ?? '')} -ErrorAction Stop; Get-Service -Name ${quote(name ?? '')} | Select-Object Name,Status | Format-Table -AutoSize | Out-String`,
          'set-startup': `Set-Service -Name ${quote(name ?? '')} -StartupType ${string(input.startup, 'startup')} -ErrorAction Stop; Get-Service -Name ${quote(name ?? '')} | Select-Object Name,Status,StartType | Format-Table -AutoSize | Out-String`,
        }
        const command = scripts[action]
        if (command === undefined) throw new Error(`Unknown action: ${action}`)
        const changes = action !== 'list' && action !== 'status'
        const line = changes && input.elevate === true
          ? await elevate(ctx, { command, required: `${action} of a service`, isElevated: async () => true }, run.agent, 'machine_service')
          : command
        return render(report(await executor.run({ command: line, timeoutMs: limits.timeoutMs }), limits.maxOutputChars))
      },
    },
    {
      name: 'machine_scheduled_task',
      description: 'Manage Windows scheduled tasks: action list, create, delete, run, enable, disable, or set. Creating or changing a task runs it at logon under the current user unless schedule says otherwise.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'create', 'delete', 'run', 'enable', 'disable', 'set'] },
          name: { type: 'string', description: 'Task name.' },
          command: { type: 'string', description: 'For create or set: the command the task runs.' },
          schedule: { type: 'string', description: 'For create: a time such as 07:30 for daily, or logon (the default).' },
          elevate: { type: 'boolean', description: 'Run as administrator through a UAC prompt.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        const action = string(input.action, 'action')
        const name = quote(input.name === undefined ? '' : string(input.name, 'name'))
        const taskCommand = input.command === undefined ? '' : string(input.command, 'command')
        const time = typeof input.schedule === 'string' && /^\d{1,2}:\d{2}$/u.test(input.schedule) ? input.schedule : undefined
        const scripts: Record<string, string> = {
          list: 'Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\\Microsoft\\*" } | Select-Object TaskName,TaskPath,State,@{n="Action";e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "}} | Format-Table -AutoSize -Wrap | Out-String',
          create: [
            `$action = New-ScheduledTaskAction -Execute ${quote(taskCommand)}`,
            `$trigger = ${time === undefined ? 'New-ScheduledTaskTrigger -AtLogOn' : `New-ScheduledTaskTrigger -Daily -At ${quote(time)}`}`,
            `Register-ScheduledTask -TaskName ${name} -Action $action -Trigger $trigger -Description 'Created by DSH machine control' -Force | Out-Null`,
            `Get-ScheduledTask -TaskName ${name} | Select-Object TaskName,State | Format-Table -AutoSize | Out-String`,
          ].join('\n'),
          delete: `Unregister-ScheduledTask -TaskName ${name} -Confirm:$false -ErrorAction Stop; 'deleted ' + ${name}`,
          run: `Start-ScheduledTask -TaskName ${name} -ErrorAction Stop; 'started ' + ${name}`,
          enable: `Enable-ScheduledTask -TaskName ${name} -ErrorAction Stop | Out-Null; 'enabled ' + ${name}`,
          disable: `Disable-ScheduledTask -TaskName ${name} -ErrorAction Stop | Out-Null; 'disabled ' + ${name}`,
          set: `$task = Get-ScheduledTask -TaskName ${name} -ErrorAction Stop; $task.Actions = @(New-ScheduledTaskAction -Execute ${quote(taskCommand)}); Set-ScheduledTask -TaskName ${name} -Action $task.Actions -ErrorAction Stop | Out-Null; 'updated ' + ${name}`,
        }
        const command = scripts[action]
        if (command === undefined) throw new Error(`Unknown action: ${action}`)
        const line = action !== 'list' && input.elevate === true
          ? await elevate(ctx, { command, required: `${action} of a scheduled task`, isElevated: async () => true }, run.agent, 'machine_scheduled_task')
          : command
        return render(report(await executor.run({ command: line, timeoutMs: limits.timeoutMs }), limits.maxOutputChars))
      },
    },
    {
      name: 'machine_network',
      description: 'Read network state (adapters, ports, routes, dns, connections) and diagnose reachability (ping, test). firewall-list shows rules; firewall-add and firewall-remove change them and need administrator rights.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['adapters', 'ports', 'routes', 'dns', 'connections', 'ping', 'test', 'firewall-list', 'firewall-add', 'firewall-remove'] },
          target: { type: 'string', description: 'For ping and test: a host name or address. For firewall-list and firewall-remove: the rule display name.' },
          port: { type: 'integer', description: 'For test and firewall-add: the TCP port.' },
          direction: { type: 'string', enum: ['inbound', 'outbound'], description: 'For firewall-add; inbound by default.' },
          elevate: { type: 'boolean', description: 'Run a firewall change as administrator through a UAC prompt.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        const action = string(input.action, 'action')
        const target = input.target === undefined ? '' : string(input.target, 'target')
        const port = input.port === undefined ? undefined : integer(input.port, 'port')
        const scripts: Record<string, string> = {
          adapters: 'Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq "Up" } | Select-Object InterfaceAlias,@{n="IPv4";e={$_.IPv4Address.IPAddress -join ", "}},@{n="Gateway";e={$_.IPv4DefaultGateway.NextHop -join ", "}},@{n="DNS";e={$_.DNSServer.ServerAddresses -join ", "}} | Format-Table -AutoSize -Wrap | Out-String',
          ports: 'Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,OwningProcess,@{n="Process";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize | Out-String',
          routes: 'Get-NetRoute | Where-Object { $_.DestinationPrefix -notlike "ff00*" } | Sort-Object DestinationPrefix | Select-Object -First 100 DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Format-Table -AutoSize | Out-String',
          dns: 'Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias,AddressFamily,@{n="Servers";e={$_.ServerAddresses -join ", "}} | Format-Table -AutoSize | Out-String',
          connections: 'Get-NetTCPConnection -State Established | Sort-Object RemoteAddress | Select-Object -First 100 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,@{n="Process";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize | Out-String',
          ping: `Test-Connection -TargetName ${quote(target)} -Count 4 -ErrorAction Stop | Select-Object Address,Latency,Status | Format-Table -AutoSize | Out-String`,
          test: `try { $client = [System.Net.Sockets.TcpClient]::new(); $task = $client.ConnectAsync(${quote(target)}, ${String(port ?? 443)}); if ($task.Wait(4000) -and $client.Connected) { 'open: ' + ${quote(target)} + ':' + '${String(port ?? 443)}' } else { 'closed or filtered: ' + ${quote(target)} + ':' + '${String(port ?? 443)}' }; $client.Dispose() } catch { 'closed or filtered: ' + $_.Exception.Message }`,
          'firewall-list': `Get-NetFirewallRule ${target === '' ? '' : `-DisplayName ${quote(target)}`} | Where-Object { $_.Enabled -eq 'True' } | Select-Object -First 100 DisplayName,Direction,Action,Profile,Enabled | Format-Table -AutoSize -Wrap | Out-String`,
          'firewall-add': `New-NetFirewallRule -DisplayName ${quote(target)} -Direction ${input.direction === 'outbound' ? 'Outbound' : 'Inbound'} -Action Allow -Protocol TCP -LocalPort ${String(port ?? 0)} -Enabled True -ErrorAction Stop | Select-Object DisplayName,Direction,Action,Enabled | Format-Table -AutoSize | Out-String`,
          'firewall-remove': `Remove-NetFirewallRule -DisplayName ${quote(target)} -Confirm:$false -ErrorAction Stop; 'removed ' + ${quote(target)}`,
        }
        const command = scripts[action]
        if (command === undefined) throw new Error(`Unknown action: ${action}`)
        const changes = action === 'firewall-add' || action === 'firewall-remove'
        const line = changes && input.elevate === true
          ? await elevate(ctx, { command, required: `${action} of a firewall rule`, isElevated: async () => true }, run.agent, 'machine_network')
          : command
        return render(report(await executor.run({ command: line, timeoutMs: limits.timeoutMs }), limits.maxOutputChars))
      },
    },
    {
      name: 'machine_security',
      description: 'Read security posture: status (Defender, firewall, BitLocker, Secure Boot), firewall, defender, update-check, audit-policy, the installed security programs, available winget/scoop/npm upgrades, or scan status and control.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['status', 'firewall', 'defender', 'update-check', 'audit-policy', 'installed-programs', 'upgrades', 'scan-start', 'scan-cancel', 'scan-status'] },
          scan: { type: 'string', enum: ['quick', 'full'], description: 'For scan-start.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        const action = string(input.action, 'action')
        const scripts: Record<string, string> = {
          status: 'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,QuickScanEndTime | Format-List | Out-String; Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | Format-Table -AutoSize | Out-String',
          firewall: 'Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked | Format-Table -AutoSize | Out-String',
          defender: 'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntispywareEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated | Format-List | Out-String; Get-MpPreference | Select-Object DisableRealtimeMonitoring,ExclusionPath,ExclusionExtension | Format-List | Out-String',
          'update-check': 'Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetFirewallProfile | Out-Null; (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates | Select-Object Title,@{n="KB";e={$_.KBArticleIDs -join ","}},IsDownloaded | Format-Table -AutoSize -Wrap | Out-String',
          'audit-policy': 'auditpol /get /category:* | Out-String',
          'installed-programs': 'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,timestamp | Format-Table -AutoSize | Out-String',
          upgrades: [
            'if (Get-Command winget -ErrorAction SilentlyContinue) { "winget:"; (& winget upgrade --include-unknown 2>$null) | Out-String }',
            'if (Get-Command scoop -ErrorAction SilentlyContinue) { "scoop:"; (& scoop status 2>$null) | Out-String }',
            'if (Get-Command npm -ErrorAction SilentlyContinue) { "npm:"; (& npm outdated -g 2>$null) | Out-String }',
          ].join('\n'),
          'scan-start': 'Start-MpScan -ScanType ' + (input.scan === 'full' ? 'FullScan' : 'QuickScan') + ' -ErrorAction Stop; "scan started: "' + (input.scan === 'full' ? 'full' : 'quick'),
          'scan-cancel': 'Get-MpComputerStatus | Out-Null; (Get-Command Stop-MpScan -ErrorAction SilentlyContinue) | Out-Null; if (Get-Command Unprotect-MpObject -ErrorAction SilentlyContinue) {}; "No cancel command is documented; a scan can be stopped only from Windows Security."',
          'scan-status': 'Get-MpComputerStatus | Select-Object ScanParameters,QuickScanStartTime,QuickScanEndTime,FullScanStartTime,FullScanEndTime | Format-List | Out-String',
        }
        const command = scripts[action]
        if (command === undefined) throw new Error(`Unknown action: ${action}`)
        return render(report(await executor.run({ command, timeoutMs: limits.timeoutMs }), limits.maxOutputChars))
      },
    },
    {
      name: 'machine_packages',
      description: 'Manage software with winget, scoop and npm: action search, list, install, uninstall, upgrade or source. A package manager that needs administrator rights asks through a UAC prompt when elevate is set.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['search', 'list', 'install', 'uninstall', 'upgrade', 'source'] },
          manager: { type: 'string', enum: ['winget', 'scoop', 'npm'], description: 'Package manager; winget by default.' },
          package: { type: 'string', description: 'Package id or name.' },
          elevate: { type: 'boolean', description: 'Run as administrator through a UAC prompt.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        const action = string(input.action, 'action')
        const manager = typeof input.manager === 'string' ? input.manager : 'winget'
        const pkg = typeof input.package === 'string' ? input.package : ''
        const argsByManager: Record<string, Record<string, string>> = {
          winget: { search: `search ${pkg}`, list: 'list --accept-source-agreements', install: `install --id ${pkg} -e --accept-package-agreements --accept-source-agreements`, uninstall: `uninstall --id ${pkg} -e`, upgrade: `upgrade --id ${pkg} -e --accept-package-agreements --accept-source-agreements`, source: 'source list' },
          scoop: { search: `search ${pkg}`, list: 'list', install: `install ${pkg}`, uninstall: `uninstall ${pkg}`, upgrade: `update ${pkg}`, source: 'bucket list' },
          npm: { search: `search ${pkg}`, list: 'ls -g --depth=0', install: `install -g ${pkg}`, uninstall: `uninstall -g ${pkg}`, upgrade: `update -g ${pkg}`, source: 'config get registry' },
        }
        const command = argsByManager[manager]?.[action]
        if (command === undefined) throw new Error(`Unknown action: ${action}`)
        const changes = action === 'install' || action === 'uninstall' || action === 'upgrade'
        const line = changes && input.elevate === true
          ? await elevate(ctx, { command: `& ${manager} ${command} 2>&1 | Out-String`, required: `${action} of ${pkg} with ${manager}`, isElevated: async () => true }, run.agent, 'machine_packages')
          : `& ${manager} ${command} 2>&1 | Out-String`
        return render(report(await executor.run({ command: line, timeoutMs: limits.maxTimeoutMs }), limits.maxOutputChars))
      },
    },
    {
      name: 'machine_disk',
      description: 'Read and reclaim space: action volumes, usage (largest folders and files under a path), clean-temp (deletes temporary files), or expand (grow a partition into adjacent unallocated space).',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['volumes', 'usage', 'clean-temp', 'expand'] },
          path: { type: 'string', description: 'For usage: the directory to measure; the user profile by default.' },
          drive: { type: 'string', description: 'For expand: the drive letter, such as C.' },
          elevate: { type: 'boolean', description: 'Run a change as administrator through a UAC prompt.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        const action = string(input.action, 'action')
        const path = typeof input.path === 'string' ? input.path : '$env:USERPROFILE'
        const drive = (typeof input.drive === 'string' ? input.drive : 'C').replace(/:$/u, '')
        const scripts: Record<string, string> = {
          volumes: 'Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter,FileSystemLabel,FileSystem,HealthStatus,@{n="SizeGB";e={[math]::Round($_.Size/1GB,1)}},@{n="FreeGB";e={[math]::Round($_.SizeRemaining/1GB,1)}} | Format-Table -AutoSize | Out-String',
          usage: [
            `$root = ${quote(path)}`,
            `Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object { $size = (Get-ChildItem -LiteralPath $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; [pscustomobject]@{ Item = $_.FullName; SizeGB = [math]::Round($size/1GB,2) } } | Sort-Object -Property SizeGB -Descending | Select-Object -First 15 | Format-Table -AutoSize -Wrap | Out-String`,
            `Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue | Sort-Object -Property Length -Descending | Select-Object -First 10 FullName,@{n="SizeMB";e={[math]::Round($_.Length/1MB,1)}} | Format-Table -AutoSize -Wrap | Out-String`,
          ].join('\n'),
          'clean-temp': [
            `$before = (Get-PSDrive ${quote(drive)}).Free`,
            `Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue`,
            `$after = (Get-PSDrive ${quote(drive)}).Free`,
            `'freed ' + [math]::Round(($after - $before)/1MB,1) + ' MB from ' + $env:TEMP`,
          ].join('\n'),
          expand: [
            `$partition = Get-Partition -DriveLetter ${quote(drive)} -ErrorAction Stop`,
            `$supported = Get-PartitionSupportedSize -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -ErrorAction Stop`,
            `if ($supported.SizeMax -le $partition.Size) { 'no unallocated space next to ' + ${quote(drive)} } else { Resize-Partition -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -Size $supported.SizeMax -ErrorAction Stop; 'expanded ' + ${quote(drive)} + ' to ' + [math]::Round($supported.SizeMax/1GB,1) + ' GB' }`,
          ].join('\n'),
        }
        const command = scripts[action]
        if (command === undefined) throw new Error(`Unknown action: ${action}`)
        const changes = action === 'clean-temp' || action === 'expand'
        const line = changes && input.elevate === true
          ? await elevate(ctx, { command, required: `${action} on the disk`, isElevated: async () => true }, run.agent, 'machine_disk')
          : command
        return render(report(await executor.run({ command: line, timeoutMs: limits.maxTimeoutMs }), limits.maxOutputChars))
      },
    },
    {
      name: 'machine_maintenance',
      description: 'Housekeeping actions: reboot, shutdown, logoff, restart-explorer, clear-dns, flush-network, windows-update-list, windows-update-install. Reboot and shutdown end every session on this machine; confirm with the user first.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['reboot', 'shutdown', 'logoff', 'restart-explorer', 'clear-dns', 'flush-network', 'windows-update-list', 'windows-update-install'] },
          delaySeconds: { type: 'integer', description: 'For reboot and shutdown: seconds before the action; 60 by default.' },
          cancel: { type: 'boolean', description: 'For reboot and shutdown: cancel a pending one instead.' },
          elevate: { type: 'boolean', description: 'Run as administrator through a UAC prompt.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        const action = string(input.action, 'action')
        const delay = input.delaySeconds === undefined ? 60 : integer(input.delaySeconds, 'delaySeconds')
        const scripts: Record<string, string> = {
          reboot: input.cancel === true ? 'shutdown.exe /a; "pending restart cancelled"' : `shutdown.exe /r /t ${String(delay)} /d p:4:1; 'restart scheduled in ${String(delay)} s'`,
          shutdown: input.cancel === true ? 'shutdown.exe /a; "pending shutdown cancelled"' : `shutdown.exe /s /t ${String(delay)} /d p:4:1; 'shutdown scheduled in ${String(delay)} s'`,
          logoff: 'logoff.exe; "logging off"',
          'restart-explorer': '(Get-Process explorer -ErrorAction SilentlyContinue) | Stop-Process -Force; Start-Process explorer.exe; "explorer restarted"',
          'clear-dns': 'Clear-DnsClientCache; ipconfig /flushdns | Out-String',
          'flush-network': 'ipconfig /release 2>&1 | Out-String; ipconfig /renew 2>&1 | Out-String; ipconfig /flushdns | Out-String',
          'windows-update-list': '(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates | Select-Object Title,@{n="KB";e={$_.KBArticleIDs -join ","}},IsDownloaded | Format-Table -AutoSize -Wrap | Out-String',
          'windows-update-install': [
            '$session = New-Object -ComObject Microsoft.Update.Session',
            '$installer = $session.CreateUpdateInstaller()',
            '$installer.Updates = $session.CreateUpdateSearcher().Search("IsInstalled=0").Updates',
            '$result = $installer.Install()',
            '"result code: " + $result.ResultCode',
            'Get-WinEvent -LogName System -MaxEvents 200 | Where-Object { $_.Id -eq 19 } | Select-Object -First 3 TimeCreated,@{n="Update";e={$_.Properties[0].Value}} | Format-Table -AutoSize | Out-String',
          ].join('\n'),
        }
        const command = scripts[action]
        if (command === undefined) throw new Error(`Unknown action: ${action}`)
        const needsElevation = action === 'flush-network' || action === 'windows-update-install'
        const line = needsElevation && input.elevate === true
          ? await elevate(ctx, { command, required: action, isElevated: async () => true }, run.agent, 'machine_maintenance')
          : command
        return render(report(await executor.run({ command: line, timeoutMs: limits.maxTimeoutMs }), limits.maxOutputChars))
      },
    },
    {
      name: 'machine_event-logs',
      description: 'Read Windows event logs: the newest events of one log, optionally filtered by level and a message pattern, or list the available logs.',
      parameters: {
        type: 'object',
        properties: {
          log: { type: 'string', description: 'Log name, such as System, Application, Security, Setup, or a channel path; omitting it lists the logs.' },
          levels: { type: 'string', description: 'Comma-separated levels to keep: critical, error, warning, information.' },
          filter: { type: 'string', description: 'A regular expression the message must match.' },
          count: { type: 'integer', description: 'Number of events, at most 50; 20 by default.' },
        },
        required: [],
        additionalProperties: false,
      },
      output: textOutput,
      execute: async (args: unknown, run: ToolRunContext) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
        if (input.log === undefined) {
          const outcome = await executor.run({ command: 'Get-WinEvent -ListLog * | Select-Object LogName,RecordCount,IsEnabled | Format-Table -AutoSize | Out-String', timeoutMs: limits.timeoutMs })
          return render(report(outcome, limits.maxOutputChars))
        }
        const log = quote(string(input.log, 'log'))
        const count = input.count === undefined ? 20 : Math.min(integer(input.count, 'count'), 50)
        const levelMap: Record<string, number> = { critical: 1, error: 2, warning: 3, information: 4 }
        const levels = typeof input.levels === 'string'
          ? input.levels.split(',').map(part => levelMap[part.trim().toLowerCase()]).filter((level): level is number => level !== undefined)
          : []
        const where = [levels.length > 0 ? `(${levels.map(level => `$_.Level -eq ${String(level)}`).join(' -or ')})` : '', typeof input.filter === 'string' && input.filter !== '' ? `($_.Message -match ${quote(input.filter)})` : ''].filter(part => part !== '')
        const filter = where.length === 0 ? '' : ` | Where-Object { ${where.join(' -and ')} }`
        const command = `Get-WinEvent -LogName ${log} -MaxEvents ${String(count * 10)} -ErrorAction Stop${filter} | Select-Object -First ${String(count)} TimeCreated,Id,LevelDisplayName,ProviderName,@{n="Message";e={($_.Message -split "\`n")[0]}} | Format-Table -AutoSize -Wrap | Out-String`
        return render(report(await executor.run({ command, timeoutMs: limits.timeoutMs }), limits.maxOutputChars))
      },
    },
  ]

  return tools.map(tool => ctx.tools.register({
    name: tool.name,
    description: tool.description,
    parameters: tool.parameters,
    output: tool.output,
    execute: tool.execute,
  }))
}

/**
 * Add the machine catalog to the system prompt.
 * @param ctx - the plugin context, which provides `ctx.systemPrompt`.
 * @param limits - whether the catalog is included.
 * @returns the disposer removing the section.
 */
export function registerGuide(ctx: Context, limits: ToolLimits): () => void {
  if (!limits.guide) return () => {}
  return ctx.systemPrompt.section({ name: 'machine-control', order: 60, text: GUIDE })
}

/** Describe a command line for one elevated run; the model never sees this type. */
export type { ElevatedCommand }
