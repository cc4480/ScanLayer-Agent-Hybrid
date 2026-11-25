'use strict';
// Catalog: the target's real tool inventory (catalog.json from inventory-qnx.sh)
// joined with tool knowledge, turned into typed stubs, and searched.
const fs = require('fs');
const { lookup } = require('./knowledge');
const { sha256 } = require('./canon');

const RESULT_TYPE = '{exit: number, signal: number, stdout: string, stderr: string, truncated: boolean, timed_out: boolean, duration_ms: number, receipt: string}';

function identFor(name, taken) {
  let id = name.replace(/[^A-Za-z0-9_]/g, '_');
  if (!/^[A-Za-z_]/.test(id)) id = '_' + id;
  if (['constructor', 'prototype', '__proto__', 'toString', 'valueOf', 'then'].includes(id)) id = id + '_';
  let k = id, n = 2;
  while (taken.has(k)) k = `${id}_${n++}`;
  taken.add(k);
  return k;
}

function tokenize(s) {
  return String(s).toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 1 && !STOP.has(w));
}
const STOP = new Set(['the', 'a', 'an', 'of', 'to', 'and', 'or', 'for', 'in', 'on', 'with', 'by', 'is', 'are', 'what', 'which', 'show', 'me', 'all', 'get', 'list', 'find', 'any', 'my', 'this', 'that', 'it', 'run', 'use', 'tool', 'tools', 'target', 'qnx', 'via']);
const SYN = {
  port: ['listeners', 'ports', 'sockets'], ports: ['listeners', 'port'], listening: ['listeners'], listener: ['listeners'], open: ['listeners', 'ports'],
  process: ['processes', 'pidin', 'ps'], processes: ['process'], running: ['process'], task: ['process'],
  log: ['log', 'syslog', 'slog2info'], logs: ['log'], network: ['network', 'interfaces'], ip: ['ip address', 'interfaces'], interface: ['interfaces'],
  route: ['routes'], routing: ['routes'], scan: ['scan', 'ports', 'reachability'], ping: ['reachability', 'icmp'], reachable: ['reachability'],
  memory: ['memory', 'ram'], cpu: ['cpu', 'load'], file: ['files', 'read file'], files: ['files'], read: ['read file', 'contents'], permission: ['permissions'],
  writable: ['world-writable', 'permissions'], version: ['version', 'build info'], versions: ['version'], driver: ['resource manager', 'driver'], device: ['devices', 'resource manager', 'dev'],
  kill: ['kill', 'signal'], disk: ['disk', 'filesystem'], hash: ['hash', 'integrity'], packets: ['packets', 'capture'], capture: ['capture', 'packets'], dns: ['dns', 'resolve'], http: ['http', 'web'],
};

class Catalog {
  constructor(doc, opts = {}) {
    this.doc = doc;
    this.allowDestructive = !!opts.allowDestructive;
    this.meta = doc.meta || {};
    const taken = new Set();
    this.tools = (doc.tools || []).map((t) => {
      const k = lookup(t.name);
      const cls = k ? k.cls : 'destructive';
      const known = !!k;
      const desc = k ? k.desc : 'Unclassified executable found in the image. Treated as destructive until classified (fail closed).';
      const tool = {
        name: t.name, path: t.path, ident: identFor(t.name, taken), cls, known,
        destructive: cls === 'destructive', network: cls === 'net' || !!(k && k.network),
        qnx: !!(k && k.qnx), desc, tags: (k && k.tags) || [], argRules: (k && k.argRules) || null,
      };
      tool.stub = `${tool.ident}(args?: string[], opts?: {timeout_ms?: number}) -> Promise<${RESULT_TYPE}>`;
      tool.words = new Set([...tokenize(t.name), ...tokenize(desc), ...tool.tags.flatMap(tokenize)]);
      return tool;
    });
    this.byIdent = new Map(this.tools.map((t) => [t.ident, t]));
    this.byName = new Map(this.tools.map((t) => [t.name, t]));
    this.hash = sha256(JSON.stringify(doc.tools || []));
  }

  static load(file, opts) { return new Catalog(JSON.parse(fs.readFileSync(file, 'utf8')), opts); }

  visible(t) { return t.cls !== 'destructive' || this.allowDestructive; }
  visibleTools() { return this.tools.filter((t) => this.visible(t)); }

  search({ query = '', names, limit = 8, include_hidden = false } = {}) {
    limit = Math.max(1, Math.min(20, limit | 0 || 8));
    let picked;
    if (Array.isArray(names) && names.length) {
      picked = names.map((n) => this.byName.get(n) || this.byIdent.get(n)).filter(Boolean).map((t) => ({ t, score: 100 }));
    } else {
      const q = tokenize(query);
      const qx = new Set(q.flatMap((w) => [w, ...(SYN[w] || []).flatMap(tokenize)]));
      picked = [];
      for (const t of this.tools) {
        let score = 0;
        const lname = t.name.toLowerCase();
        for (const w of q) { if (lname === w) score += 12; else if (lname.startsWith(w) && w.length >= 3) score += 4; }
        for (const w of qx) if (t.words.has(w)) score += 2;
        if (score === 0) continue;
        if (t.known) score += 1.5;
        if (t.qnx && this.meta.os === 'QNX') score += 1;
        if (!this.visible(t)) score -= include_hidden ? 1 : 3;
        picked.push({ t, score });
      }
      picked.sort((a, b) => b.score - a.score || a.t.name.localeCompare(b.t.name));
    }
    const matches = picked.slice(0, limit).map(({ t }) => ({
      name: t.name,
      call: `tools.${t.ident}`,
      stub: t.stub,
      summary: t.desc.slice(0, 200),
      path: t.path,
      class: t.cls,
      network: t.network,
      callable: this.visible(t),
      ...(this.visible(t) ? {} : { why_not: 'destructive: off by default on QNX; an operator must enable destructive tools explicitly' }),
    }));
    return { matches, catalog_size: this.tools.length, visible_size: this.visibleTools().length };
  }

  /** Read-only facts the sandbox exposes as `catalog` (no paths of secrets, no raw dumps). */
  snapshot() {
    const n = this.doc.network || {};
    return {
      meta: this.meta,
      processes: this.doc.processes || [],
      resource_managers: this.doc.resource_managers || [],
      network: { interfaces: n.interfaces || [], interface_ips: n.interface_ips || [], listeners: n.listeners || [], commands: n.commands || {} },
      tool_names: this.tools.map((t) => t.name),
    };
  }

  /** Allowlist for the runner: absolute paths of every callable tool. */
  allowlist(extra = []) { return [...this.visibleTools().map((t) => t.path), ...extra].join('\n') + '\n'; }
}

module.exports = { Catalog, RESULT_TYPE };
