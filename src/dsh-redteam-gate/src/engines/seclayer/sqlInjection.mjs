// SQL injection probe, error-based detection only (ported from server/redTeam/sqlInjection.ts).
// Injects a quote boundary into "id" and reports only a raw database-engine error signature. A
// differential check against a benign id=1 request suppresses signatures that are static page content.

import { buildEvidence } from './evidence.mjs'
import { createScopedFetch, normalizeTarget } from './gate.mjs'
import { signaturePreexists } from './baseline.mjs'

export const name = 'sql-injection'
export const owaspCategory = 'A03:2021-Injection'

// Specific raw database-engine error texts only. Bare "syntax error" is deliberately not matched.
export const SQL_ERROR_SIGNATURE =
  /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|SQLITE_ERROR|near \\?".*?\\?": syntax error|syntax error at (?:or near|end of input)|unterminated quoted (?:string|identifier) at or near|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i

export async function run(target, opts = {}, fetchFn = globalThis.fetch) {
  const base = normalizeTarget(target)
  const get = createScopedFetch({ fetchFn, gate: opts.gate, headers: opts.headers, timeoutMs: opts.timeoutMs })

  const attackUrl = `${base}/?id=%27%20OR%201%3D1--`
  const res = await get(attackUrl)
  const match = SQL_ERROR_SIGNATURE.exec(res.body)
  if (!match) return null

  // A signature that also appears for a benign value is page content, not injection.
  if (await signaturePreexists(get, `${base}/?id=1`, SQL_ERROR_SIGNATURE)) return null

  return {
    module: name,
    owaspCategory,
    testName: 'Active SQL Injection Probe',
    payload: "' OR 1=1--",
    severity: 'critical',
    description: 'A raw database error appeared only after a quote boundary was injected into the "id" parameter.',
    fix: 'Use parameterized queries or prepared statements. Do not concatenate input into SQL.',
    evidence: buildEvidence({
      method: 'error-signature',
      attackUrl,
      status: res.status,
      contentType: res.contentType,
      body: res.body,
      matchIndex: match.index,
      quote: match[0],
      why: 'A raw database-engine error is emitted only when the injected quote breaks the SQL syntax. A benign value does not produce it.',
      demonstration: `Injected "' OR 1=1--" into "id"; the server returned the raw database error "${match[0]}".`,
    }),
  }
}
