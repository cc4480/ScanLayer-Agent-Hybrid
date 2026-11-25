'use strict';
// Minimal MCP (Streamable HTTP) + operator-API client. Used by the verifier
// seat, the ladder script and the tests; any MCP client (the DeepSeek super
// harness, Claude Code, ...) talks to the gateway the same way.
const http = require('http');

function request(base, token, method, path, body) {
  const u = new URL(path, base);
  const data = body === undefined ? null : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...(data ? { 'content-length': Buffer.byteLength(data) } : {}) } }, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (d) => (buf += d));
      res.on('end', () => { let json = null; try { json = buf ? JSON.parse(buf) : null; } catch {} resolve({ status: res.statusCode, json, text: buf }); });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

class McpClient {
  constructor(base, token) { this.base = base; this.token = token; this.id = 0; }
  async rpc(method, params) {
    const r = await request(this.base, this.token, 'POST', '/mcp', { jsonrpc: '2.0', id: ++this.id, method, params });
    if (r.status !== 200) { const e = new Error(`HTTP ${r.status}`); e.status = r.status; e.body = r.json; throw e; }
    if (r.json.error) throw new Error(r.json.error.message);
    return r.json.result;
  }
  initialize() { return this.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'qnx-agent-client', version: '0.1.0' } }); }
  async listTools() { return (await this.rpc('tools/list', {})).tools; }
  async search(query, limit = 8) { return (await this.rpc('tools/call', { name: 'search', arguments: { query, limit } })).structuredContent; }
  async execute(program, timeout_ms) { return (await this.rpc('tools/call', { name: 'execute', arguments: { program, ...(timeout_ms ? { timeout_ms } : {}) } })).structuredContent; }
  get(path) { return request(this.base, this.token, 'GET', path); }
  post(path, body = {}) { return request(this.base, this.token, 'POST', path, body); }
}

module.exports = { McpClient, request };
