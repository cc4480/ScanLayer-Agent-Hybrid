// Native process runner for the installed security tools.
// Arguments are passed as an array (never through a shell), so a model-supplied string cannot inject
// commands. Output is capped; the process is killed on timeout or abort.
import { execFile } from 'node:child_process'

export const MAX_OUTPUT_BYTES = 256 * 1024

/** Split a flags string into argv tokens. Shell metacharacters are refused rather than interpreted. */
export function splitFlags(flags) {
  if (flags === undefined || flags === null || String(flags).trim() === '') return []
  const s = String(flags)
  if (/[;&|`$<>(){}\n\r]/.test(s)) {
    throw new Error('flags contain shell metacharacters; pass each option as a plain token')
  }
  return s.trim().split(/\s+/)
}

/**
 * Run a binary with an argv array.
 * @param {string} binary - absolute path to the executable
 * @param {string[]} argv
 * @param {{timeoutMs?: number, signal?: AbortSignal, cwd?: string}} opts
 * @returns {Promise<{exitCode: number|null, stdout: string, stderr: string, truncated: boolean, timedOut: boolean}>}
 */
export function runTool(binary, argv, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 300_000
  return new Promise((resolve) => {
    execFile(
      binary,
      argv,
      {
        timeout: timeoutMs,
        signal: opts.signal,
        windowsHide: true,
        maxBuffer: MAX_OUTPUT_BYTES * 4,
        cwd: opts.cwd,
        env: opts.env,
      },
      (error, stdout, stderr) => {
        const out = String(stdout ?? '')
        const err = String(stderr ?? '')
        const truncated = Buffer.byteLength(out) > MAX_OUTPUT_BYTES
        const clip = (s) => (Buffer.byteLength(s) > MAX_OUTPUT_BYTES ? s.slice(0, MAX_OUTPUT_BYTES) : s)
        const timedOut = Boolean(error && (error.killed || error.signal === 'SIGTERM') && timeoutMs)
        resolve({
          exitCode: error ? (typeof error.code === 'number' ? error.code : null) : 0,
          stdout: clip(out),
          stderr: clip(err),
          truncated,
          timedOut,
          spawnError: error && typeof error.code === 'string' ? error.code : undefined,
        })
      },
    )
  })
}
