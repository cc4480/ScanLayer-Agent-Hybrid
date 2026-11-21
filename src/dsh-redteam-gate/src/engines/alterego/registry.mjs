// Registers the AlterEgo catalog as native harness tools.
//
// Every tool comes from catalog.json (generated from the AlterEgo wrappers by
// scripts/gen-alterego-catalog.py) and runs through the adapter in bridge.mjs, in a short-lived
// Python child. Nothing is sent over MCP or HTTP. Each registered name carries AE_PREFIX so it cannot
// shadow a harness tool. The scope rules for these tools are in src/alterego-scope.mjs.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { invokePcAgent } from './bridge.mjs'
import { AE_PREFIX } from '../../alterego-scope.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
export const CATALOG = JSON.parse(readFileSync(path.join(HERE, 'catalog.json'), 'utf8'))

// Item types for list parameters. Anything not listed is an untyped list of strings.
const ARRAY_ITEMS = { ports: 'integer', options: 'string', plan: 'string', calls: 'object', trajectories: 'object', steps: 'object' }

// Rendered text is capped so one large result (a screenshot, a long file) cannot flood the model.
const RENDER_LIMIT = 200_000

const OUTPUT = {
  // Each wrapper returns its own JSON shape, so the object is open. DSH requires the flag to be explicit.
  schema: { type: 'object', additionalProperties: true },
  render: (_args, value) => {
    const text = JSON.stringify(value)
    return [{ type: 'text', text: text.length > RENDER_LIMIT ? `${text.slice(0, RENDER_LIMIT)}…[truncated]` : text }]
  },
}

function harnessParameters(entry) {
  const parameters = {}
  for (const [name, p] of Object.entries(entry.parameters)) {
    const spec = { type: p.type, description: p.default === undefined ? p.description : `${p.description} (default ${JSON.stringify(p.default)})` }
    // DSH requires additionalProperties to be explicit on every object schema, including list items.
    if (p.type === 'object') spec.additionalProperties = true
    if (p.type === 'array') {
      const itemType = ARRAY_ITEMS[name] ?? 'string'
      spec.items = itemType === 'object' ? { type: 'object', additionalProperties: true } : { type: itemType }
    }
    if (entry.required.includes(name)) spec.required = true
    parameters[name] = spec
  }
  return parameters
}

function timeoutFor(args) {
  const seconds = Number(args?.timeout_s)
  return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 3600) * 1000 + 30_000 : 90_000
}

/** One harness tool per registered catalog entry. */
export function alterEgoTools({ invoke = invokePcAgent } = {}) {
  return CATALOG.tools.filter((t) => t.registered).map((entry) => defineTool({
    name: `${AE_PREFIX}${entry.name}`,
    description: `${entry.description} [AlterEgo ${entry.name}, native]`,
    parameters: harnessParameters(entry),
    output: OUTPUT,
    async execute(args) {
      const envelope = await invoke(entry.name, args ?? {}, { timeoutMs: timeoutFor(args) })
      if (!envelope || envelope.ok !== true) {
        throw new Error(envelope?.error || `AlterEgo ${entry.name} failed`)
      }
      return envelope.result
    },
  }))
}
