/**
 * Hook the reader's decision: one in-app approval answer, or one Quit control, writes a small JSON plan file into the
 * user's LocalAppData folder. A DSH hook calls `dsh-machine-control apply-plan` with that file to perform the action: the
 * one-shot plugin cannot run a multi-hour command itself.
 */
import type { CommandOutcome, Executor } from './exec.ts'

/** Actions a plan file may ask for. */
export const PLAN_ACTIONS = ['reboot', 'shutdown', 'logoff', 'reboot-update', 'explorer', 'flush-dns'] as const

/** One plan file's accepted shape. */
export interface QuitPlan {
  readonly kind: string
  readonly name?: string | undefined
  readonly action: (typeof PLAN_ACTIONS)[number]
  readonly delaySeconds?: number | undefined
}

/** The script body that filters a message stream down to the lines the page shows. */
export function filterScript(filter: string): string {
  const pattern = `'${filter.replaceAll("'", "''")}'`
  return `$clauses = ${pattern}.Split('|') | Where-Object { $_ -ne '' } | ForEach-Object { $_ -split ':' }\n` +
    `$lines = $input | Where-Object { $_ -ne $null }\n` +
    `$lines | Where-Object { $line = $_; $keep = $true; foreach ($clause in $clauses) { if ($line -notmatch $clause) { $keep = $false } }; $keep }\n`
}

/**
 * The script that performs one plan action.
 * @param plan - the validated plan.
 * @returns the PowerShell text.
 */
export function planScript(plan: QuitPlan): string {
  const delay = plan.delaySeconds === undefined ? 30 : Math.trunc(plan.delaySeconds)
  switch (plan.action) {
    case 'reboot': return 'shutdown.exe /r /t ' + String(delay) + ' /d p:4:1'
    case 'shutdown': return 'shutdown.exe /s /t ' + String(delay) + ' /d p:4:1'
    case 'logoff': return 'logoff.exe'
    case 'reboot-update': return 'Install-WindowsUpdate -AcceptAll -AutoReboot'
    case 'explorer': return '(Get-Process explorer -ErrorAction SilentlyContinue) | Stop-Process -Force; Start-Process explorer.exe'
    case 'flush-dns': return 'Clear-DnsClientCache'
  }
}

/**
 * Validate a parsed plan file.
 * @param value - the parsed JSON.
 * @returns the plan.
 * @throws {Error} naming the first problem found, so the page can show why the plan is refused.
 */
export function parsePlan(value: unknown): QuitPlan {
  if (typeof value !== 'object' || value === null) throw new Error('The plan file must contain a JSON object.')
  const plan = value as Record<string, unknown>
  if (typeof plan.kind !== 'string' || plan.kind.trim() === '') throw new Error('The plan file needs a "kind".')
  if (typeof plan.action !== 'string' || !(PLAN_ACTIONS as readonly string[]).includes(plan.action)) {
    throw new Error(`The "action" must be one of: ${PLAN_ACTIONS.join(', ')}.`)
  }
  if (plan.name !== undefined && typeof plan.name !== 'string') throw new Error('"name" must be a string.')
  if (plan.delaySeconds !== undefined && (typeof plan.delaySeconds !== 'number' || !Number.isFinite(plan.delaySeconds))) {
    throw new Error('"delaySeconds" must be a number.')
  }
  return {
    kind: plan.kind,
    name: typeof plan.name === 'string' ? plan.name : undefined,
    action: plan.action as QuitPlan['action'],
    delaySeconds: typeof plan.delaySeconds === 'number' ? plan.delaySeconds : undefined,
  }
}

/**
 * Apply a plan read from a file.
 * @param exec - the executor that runs the action's command.
 * @param planPath - path of the plan file, as the user's hook passes it.
 * @returns the plan and the command outcome.
 */
export async function applyPlan(exec: Executor, planPath: string): Promise<{ plan: QuitPlan; outcome: CommandOutcome }> {
  const { readFile } = await import('node:fs/promises')
  const plan = parsePlan(JSON.parse(await readFile(planPath, 'utf8')) as unknown)
  const outcome = await exec.run({ command: planScript(plan), timeoutMs: 12 * 60 * 60 * 1000 })
  return { plan, outcome }
}
