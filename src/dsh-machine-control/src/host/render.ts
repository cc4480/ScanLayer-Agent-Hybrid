/** Render tool output for the model as compact text tables. */
import type { Fact, PanelData, Table } from '../types.ts'

/** Format one table as a fixed-width text block. */
function renderTable(table: Table): string {
  const rows = [table.columns, ...table.rows]
  const widths = table.columns.map((_column, index) => Math.max(...rows.map(row => (row[index] ?? '').length)))
  const line = (row: readonly string[]): string => row.map((cell, index) => (cell ?? '').padEnd(widths[index] ?? 0)).join('  ').trimEnd()
  const blocks = [line(table.columns), widths.map(width => '-'.repeat(width)).join('  ')]
  for (const row of table.rows) blocks.push(line(row))
  if (table.truncated !== undefined) blocks.push(`[${String(table.truncated)} more rows not shown]`)
  return blocks.join('\n')
}

/** Format facts as one line each. */
function renderFacts(facts: ReadonlyArray<Fact>): string {
  return facts.map(fact => `${fact.label}: ${fact.value}`).join('\n')
}

/**
 * Format a collected page for the model.
 * @param data - the collected facts and tables.
 * @returns the text the tool reports.
 */
export function renderPanel(data: PanelData): string {
  const parts: string[] = []
  if (data.facts.length > 0) parts.push(renderFacts(data.facts))
  for (const table of data.tables) parts.push(`${table.title}\n${renderTable(table)}`)
  if (data.notes.length > 0) parts.push(data.notes.map(note => `note: ${note}`).join('\n'))
  return parts.join('\n\n') === '' ? 'No data.' : parts.join('\n\n')
}
