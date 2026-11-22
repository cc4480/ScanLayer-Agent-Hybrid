import { expect, it } from 'vitest'
import { Engine, MemoryRepositories, runningAssignment, ticketStage } from '../src/core/index.ts'
import type { Candidate, OutboundMessage } from '../src/core/index.ts'
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
it('turns one local request into a running ticket that has no Channel', () => {
  const repo = new MemoryRepositories()
  const started: string[] = []
  const outbox: OutboundMessage[] = []
  const candidates: Candidate[] = []
  const engine = new Engine({ repo, scope, policy: () => policy(),
    assessor: { request: candidate => { candidates.push(candidate) } },
    executor: { start: ticket => { started.push(ticket.id) }, deliver: () => {}, stop: () => {} },
    outbox: { send: message => { outbox.push(message) }, status: () => undefined, withdraw: () => {} },
    now: () => '2026-01-01T00:00:00.000Z' })
  const trigger = manualTrigger({ text: 'Fix the failing test', title: 'Fix it', at: '2026-01-01T00:00:00.000Z' })
  expect(engine.receive(trigger)).toBe('stored')
  // Receiving queues the Trigger for an Eval; deciding it at once withdraws it again instead of waiting for the assessor.
  expect(candidates).toEqual([])
  const decision = engine.decide(trigger.id, { kind: 'accept', title: 'Fix it', scope: 'local work', reason: { code: 'personRequest' } })
  expect(decision).toMatchObject({ kind: 'accept', ticketId: expect.any(String) })
  const ticket = repo.tickets.get(decision.ticketId!)!
  expect(ticket).toMatchObject({ title: 'Fix it', channels: [] })
  expect(ticket.mandate).toMatchObject({ strength: 'explicit',
    basis: { via: 'addressed', addressed: 'direct', source: MANUAL_SOURCE } })
  expect(trigger.threads.map(ref => `${ref.source}:${ref.id}`)).toEqual([threadOf(trigger).key])
  expect(repo.threads.get(threadOf(trigger).key)?.subscriptions).toEqual([ticket.id])
  // The Executor is handed the pending Assignment as the ticket is created, and starts it on its next step.
  expect(started).toEqual([ticket.id])
  expect(ticketStage(ticket)).toEqual({ stage: 'working', action: 'queued' })
  const assignment = ticket.assignments[0]!
  engine.assignmentStarted(ticket.id, assignment.id)
  expect(runningAssignment(repo.tickets.get(ticket.id)!)).toMatchObject({ id: assignment.id, state: 'running' })
  expect(ticketStage(repo.tickets.get(ticket.id)!)).toEqual({ stage: 'working' })
  // Local work has no conversation, so accepting it queues no acknowledgement anywhere.
  expect(outbox).toEqual([])
})

it('refuses local work while the local Source is off', () => {
  const repo = new MemoryRepositories()
  const off = { scope: () => ({ listened: false as const, reason: 'source_disabled' }) }
  const engine = new Engine({ repo, scope: off, policy: () => settingsPolicy(settings, off),
    assessor: { request: () => {} },
    executor: { start: () => {}, deliver: () => {}, stop: () => {} },
    outbox: { send: () => {}, status: () => undefined, withdraw: () => {} } })
  const trigger = manualTrigger({ text: 'Anything', title: 'Anything', at: '2026-01-01T00:00:00.000Z' })
  expect(engine.receive(trigger)).toBe('filtered')
  expect(repo.triggers.disposition(trigger.id)?.filtered).toEqual({ code: 'source_disabled' })
  expect(() => engine.decide(trigger.id, { kind: 'accept', title: 'Anything', scope: 'local work', reason: { code: 'personRequest' } }))
    .toThrowError(/not admissible/i)
})
