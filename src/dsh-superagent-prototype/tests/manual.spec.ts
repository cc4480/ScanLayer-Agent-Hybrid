import { expect, it } from 'vitest'
import { SettingsSchema, settingsPolicy } from '../src/policy.ts'
import { MANUAL_ACTOR, MANUAL_SOURCE, manualKind, manualTrigger } from '../src/sources/manual.ts'

const scope = { scope: () => ({ listened: true as const, observed: false }) }
const settings = SettingsSchema.parse({})
const policy = (value = settings) => settingsPolicy(value, scope)
const threadOf = (trigger: ReturnType<typeof manualTrigger>) => ({ key: `${trigger.source}:${trigger.threads[0]!.id}`,
  ref: trigger.threads[0]!, createdAt: trigger.at, subscriptions: [], correlated: [], pending: [], meta: {} })

it('makes one Trigger per piece of local work, on its own Thread, from the person at the panel', () => {
  const trigger = manualTrigger({ text: 'Fix the failing test', title: 'Fix it', at: '2026-01-01T00:00:00.000Z', id: 'local-1' })
  expect(trigger).toMatchObject({ id: 'trigger-local-1', source: MANUAL_SOURCE, human: true, addressed: 'direct',
    actor: { source: MANUAL_SOURCE, id: MANUAL_ACTOR }, text: 'Fix the failing test', meta: { title: 'Fix it' } })
  expect(trigger.threads).toEqual([{ source: MANUAL_SOURCE, id: 'local-1' }])
  // No Channel: local work has no conversation to reply to.
  expect(trigger.channel).toBeUndefined()
})

it('admits the local person as an explicit request without a stored allow list', () => {
  const trigger = manualTrigger({ text: 'Write the migration', title: 'Migration', at: '2026-01-01T00:00:00.000Z' })
  expect(settings.policy.sources).toEqual({})
  const gate = policy().gate(trigger, threadOf(trigger), [])
  expect(gate).toMatchObject({ admissible: true, strength: 'explicit',
    basis: { via: 'addressed', addressed: 'direct', source: MANUAL_SOURCE } })
})

it('keeps a local Ticket valid across a Policy change', () => {
  const trigger = manualTrigger({ text: 'Ship it', title: 'Ship', at: '2026-01-01T00:00:00.000Z' })
  const active = policy()
  const gate = active.gate(trigger, threadOf(trigger), [])
  if (!gate.admissible) throw new Error('the local Trigger must be admissible')
  const mandate = { strength: gate.strength, policyVersion: active.version, basis: gate.basis, actor: trigger.actor,
    scope: 'local work' }
  expect(policy().revalidate(mandate)).toBe(true)
})

it('still refuses a stranger on a Source that has no allow list of its own', () => {
  const base = manualTrigger({ text: 'hi', title: 'hi', at: '2026-01-01T00:00:00.000Z' })
  const trigger = { ...base, source: 'github', actor: { source: 'github', id: 'stranger' },
    threads: [{ source: 'github', id: '1' }], addressed: undefined }
  const thread = { key: 'github:1', ref: trigger.threads[0]!, createdAt: trigger.at, subscriptions: [], correlated: [],
    pending: [], meta: {} }
  expect(policy().gate(trigger, thread, []).admissible).toBe(false)
})

it('takes no configuration and owns no health entry', () => {
  expect(manualKind.schema.parse({})).toEqual({})
  expect(manualKind.fields).toEqual([])
  expect(manualKind.health).toEqual([])
})