// Live scan ticker: turns the engines' own progress callbacks (SecLayer's EmitFn, VibeScan's onTest)
// into the console lines the product's own UI shows while a scan runs ("[PROBE] -> SQL injection:
// firing...", "[CHECK] Header analysis - ran"). Each line is also buffered, so a finished scan's full
// transcript can be embedded in the HTML report's "Live Scan Ticker" section.
//
// Lines are written with console.log so they appear as the tool executes, not only in its final
// result: the harness's own agent-run UI shows a tool's stdout live while it is running.

/**
 * @param {{write?: (line: string) => void}} [opts] write defaults to console.log; override for tests.
 * @returns {{
 *   onSeclayerEvent: (channel: string, text: string) => void,
 *   onVibeTest: (record: {group: string, name: string, status: string, findings: number, reason?: string, detail?: string}) => void,
 *   lines: () => string[],
 * }}
 */
export function createTicker({ write = (line) => console.log(line) } = {}) {
  const lines = []
  const emit = (line) => {
    lines.push(line)
    write(line)
  }

  /** SecLayer's EmitFn shape: (channel, text). channel is "system" | "recon" | "probe" | "result" | "flash". */
  function onSeclayerEvent(channel, text) {
    emit(`[${String(channel).toUpperCase()}] ${text}`)
  }

  /** VibeScan's onTest shape: one TestRecord per completed check. */
  function onVibeTest(record) {
    const { group, name, status, findings, reason, detail } = record ?? {}
    const parts = [`${group ?? '?'} / ${name ?? '?'}`, status ?? 'unknown']
    if (typeof findings === 'number' && findings > 0) parts.push(`${findings} finding(s)`)
    if (detail) parts.push(detail)
    if (reason) parts.push(reason)
    emit(`[CHECK] ${parts.join(' - ')}`)
  }

  return { onSeclayerEvent, onVibeTest, lines: () => lines.slice() }
}
