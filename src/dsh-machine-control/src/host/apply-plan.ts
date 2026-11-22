/**
 * Apply a plan a reader's approval answer or the Quit control wrote. A DSH hook runs this command after the one-shot
 * plugin ended: `dsh-machine-control apply-plan <path-to-plan.json>`.
 */
import { readFile, unlink } from 'node:fs/promises'
import type { CommandOutcome, Executor } from './exec.ts'
import { applyPlan, type QuitPlan } from './plan.ts'

/** What the command line reports. */
export interface ApplyPlanResult {
  readonly plan: QuitPlan
  readonly outcome: CommandOutcome
}

/**
 * Read the plan file and perform its action.
 * @param exec - the executor that runs the action.
 * @param planPath - the plan file named on the command line.
 * @returns the plan and its command outcome.
 * @throws when the file is missing or invalid; an invalid file is deleted so no later run applies it.
 */
export async function applyPlanFile(exec: Executor, planPath: string): Promise<ApplyPlanResult> {
  try {
    const { plan, outcome } = await applyPlan(exec, planPath)
    return { plan, outcome }
  } catch (error) {
    await unlink(planPath).catch((unlinkError: unknown) => {
      // The plan file may already be gone, which is the state this failure wants anyway.
      void unlinkError
    })
    throw error
  }
}

/**
 * Read a plan file without performing it, for a caller that wants to show what would happen.
 * @param planPath - the plan file.
 * @returns the raw file text.
 */
export async function readPlanText(planPath: string): Promise<string> {
  return readFile(planPath, 'utf8')
}
