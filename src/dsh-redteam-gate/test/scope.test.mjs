import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decideScope, extractHosts } from '../src/scope.mjs'

const never = { isVerified: async () => false }
const verifiedExample = { isVerified: async (d) => d === 'example.com' }
const throws = { isVerified: async () => { throw new Error('network down') } }

test('loopback native tool is allowed', async () => {
  const r = await decideScope({ toolName: 'nmap', arguments: { target: '127.0.0.1', ports: '80' } }, never)
  assert.equal(r.kind, 'allow')
})

test('namespaced MCP tool name is normalized', async () => {
  const r = await decideScope({ toolName: 'mcp__redteam__nuclei', arguments: { url: 'http://localhost:8080/' } }, never)
  assert.equal(r.kind, 'allow')
})

test('unverified domain is denied', async () => {
  const r = await decideScope({ toolName: 'ffuf', arguments: { url: 'https://victim.example.org/FUZZ' } }, never)
  assert.equal(r.kind, 'deny')
  assert.match(r.reason, /victim\.example\.org/)
})

test('verified domain is allowed', async () => {
  const r = await decideScope({ toolName: 'nuclei', arguments: { target: 'https://example.com' } }, verifiedExample)
  assert.equal(r.kind, 'allow')
})

test('a throwing verifier fails closed', async () => {
  const r = await decideScope({ toolName: 'nmap', arguments: { target: 'example.com' } }, throws)
  assert.equal(r.kind, 'deny')
})

test('public IP is denied even if the verifier says yes', async () => {
  const yes = { isVerified: async () => true }
  const r = await decideScope({ toolName: 'nmap', arguments: { target: '8.8.8.8' } }, yes)
  assert.equal(r.kind, 'deny')
})

test('active tool with no target is denied', async () => {
  const r = await decideScope({ toolName: 'nmap', arguments: { flags: '-sV' } }, never)
  assert.equal(r.kind, 'deny')
})

test('every target in an array argument is checked', async () => {
  const r = await decideScope({ toolName: 'nmap', arguments: { targets: ['127.0.0.1', 'victim.example.org'] } }, never)
  assert.equal(r.kind, 'deny')
})

test('shell invocation of an active tool against a public host is denied', async () => {
  const r = await decideScope({ toolName: 'bash', arguments: { command: 'nmap -sV 8.8.8.8' } }, never)
  assert.equal(r.kind, 'deny')
})

test('shell bypass: lab nmap chained with an outbound curl is denied', async () => {
  const r = await decideScope({ toolName: 'bash', arguments: { command: 'nmap 127.0.0.1 && curl https://evil.example.net' } }, never)
  assert.equal(r.kind, 'deny')
  assert.match(r.reason, /evil\.example\.net/)
})

test('ordinary shell commands are allowed', async () => {
  const r = await decideScope({ toolName: 'bash', arguments: { command: 'ls -la && node --version' } }, never)
  assert.equal(r.kind, 'allow')
})

test('unrelated tools are allowed', async () => {
  const r = await decideScope({ toolName: 'read_file', arguments: { path: 'notes.txt' } }, never)
  assert.equal(r.kind, 'allow')
})

test('extractHosts finds URLs, IPs, IPv6 and domains and drops ports', () => {
  const hosts = extractHosts('curl http://127.0.0.1:8080/x && nmap [::1] 10.0.0.5 foo.example.com')
  assert.ok(hosts.includes('127.0.0.1'))
  assert.ok(hosts.includes('::1'))
  assert.ok(hosts.includes('10.0.0.5'))
  assert.ok(hosts.includes('foo.example.com'))
})

test('flags cannot smuggle a second host past the gate (nmap/nuclei/ffuf/gobuster)', async () => {
  const r = await decideScope({ toolName: 'nuclei', arguments: { target: '127.0.0.1', flags: '-u https://evil.example.net' } }, never)
  assert.equal(r.kind, 'deny')
  assert.match(r.reason, /evil\.example\.net/)
})

test('a file-of-targets flag is refused for active tools', async () => {
  const r = await decideScope({ toolName: 'nmap', arguments: { target: '127.0.0.1', flags: '-iL hosts.txt' } }, never)
  assert.equal(r.kind, 'deny')
  assert.match(r.reason, /file of targets/)
})

test('a loopback target with loopback-only flags is still allowed', async () => {
  const r = await decideScope({ toolName: 'nmap', arguments: { target: '127.0.0.1', flags: '-Pn -sT -p 80' } }, never)
  assert.equal(r.kind, 'allow')
})
