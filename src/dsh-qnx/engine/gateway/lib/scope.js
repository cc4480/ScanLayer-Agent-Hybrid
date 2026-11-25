'use strict';
// Scope gate — decides, BEFORE anything spawns, whether every target named in an
// argv is in scope. Ported behavior (Parrot):
//   * targets are extracted from argv: IPv4, IPv4/CIDR, IPv6, URL host,
//     host:port, user@host, hostnames; plus QNX Qnet: /net/<node>/... paths
//     and `on -n <node>` — Qnet makes other nodes' resources local pathnames,
//     so a path can be a network target on QNX.
//   * the target itself (localhost, 127/8, ::1, its own hostname, its interface
//     IPs) is always in scope;
//   * anything else needs a VERIFIED engagement in engagements.json:
//       IP      -> exact match, or membership in an engagement CIDR
//       CIDR    -> the exact CIDR must be named (no implicit widening)
//       host    -> exact (case-insensitive) name; never resolved (resolution
//                  would itself send a packet)
//   * missing / unreadable / malformed engagements file = no engagements.
//     An engagement whose HMAC signature does not verify, or that has expired,
//     does not exist. Fail closed everywhere.
const crypto = require('crypto');
const fs = require('fs');
const { NETWORK_TOOLS } = require('./knowledge');
const { canonical } = require('./canon');

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HOSTNAME = /^(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;
const NUMERIC = /^\d+(?:[-,]\d+)*$/; // counts, ports, port ranges/lists
const SCHEME_URL = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;

function ipToInt(ip) { return ip.split('.').reduce((a, o) => ((a << 8) >>> 0) + Number(o), 0) >>> 0; }
function parseCidr(s) {
  const m = /^(.+)\/(\d{1,2})$/.exec(s);
  if (!m || !IPV4.test(m[1]) || Number(m[2]) > 32) return null;
  const bits = Number(m[2]);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return { base: (ipToInt(m[1]) & mask) >>> 0, mask, bits, text: `${m[1]}/${bits}` };
}
function inCidr(ip, c) { return ((ipToInt(ip) & c.mask) >>> 0) === c.base; }
function isIPv6(s) { return /^[0-9A-Fa-f:]+(%[A-Za-z0-9]+)?$/.test(s) && s.includes(':') && (s.match(/:/g) || []).length >= 2; }

function classify(raw) {
  let s = raw.trim();
  if (!s) return null;
  if (SCHEME_URL.test(s)) {
    try {
      const u = new URL(s);
      s = u.hostname.replace(/^\[|\]$/g, '');
      if (!s) return { kind: 'unparseable', value: raw };
    } catch { return { kind: 'unparseable', value: raw }; }
  } else {
    if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);
    const b6 = /^\[([^\]]+)\](?::\d+)?$/.exec(s);
    if (b6) s = b6[1];
    else if (/^[^:]+:\d+$/.test(s)) s = s.slice(0, s.lastIndexOf(':')); // host:port (not IPv6)
    if (s.includes('/') && !parseCidr(s)) {
      const hp = s.split('/')[0]; // host/path without scheme
      if (hp) s = hp;
    }
  }
  if (IPV4.test(s)) return { kind: 'ipv4', value: s };
  const c = parseCidr(s);
  if (c) return { kind: 'cidr', value: c.text, cidr: c };
  if (isIPv6(s)) return { kind: 'ipv6', value: s.toLowerCase() };
  if (HOSTNAME.test(s) && !NUMERIC.test(s)) return { kind: 'host', value: s.toLowerCase().replace(/\.$/, '') };
  return { kind: 'unparseable', value: raw };
}

const EMBEDDED_URL = /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s'"<>]+/g;
const EMBEDDED_IP = /(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(\/\d{1,2})?(?![\d.])/g;

/**
 * Extract every target an argv names.
 * @returns {{targets: Array<{kind,value,source}>, problems: string[]}}
 */
function extractTargets(toolName, args) {
  const targets = [];
  const problems = [];
  const add = (t, source) => { if (t && !targets.some((x) => x.kind === t.kind && x.value === t.value)) targets.push({ ...t, source }); };
  const isNet = NETWORK_TOOLS.has(toolName);

  args.forEach((arg, i) => {
    // QNX Qnet: /net/<node>/... reaches another node's resources.
    const qn = /^\/net\/([^/]+)/.exec(arg);
    if (qn) add({ kind: 'qnet', value: qn[1].toLowerCase() }, `argv[${i + 1}]`);
    // Explicit URLs / IPs anywhere, for every tool.
    for (const m of arg.matchAll(EMBEDDED_URL)) { const t = classify(m[0]); if (t) add(t, `argv[${i + 1}]`); }
    for (const m of arg.matchAll(EMBEDDED_IP)) {
      const t = classify(m[1] + (m[2] || ''));
      if (t && t.kind !== 'unparseable') add(t, `argv[${i + 1}]`);
      else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(m[1])) problems.push(`argv[${i + 1}]: malformed address "${m[0]}"`);
    }
  });

  if (toolName === 'on') {
    for (let i = 0; i < args.length; i++) {
      if ((args[i] === '-n' || args[i] === '-f') && args[i + 1]) add({ kind: 'qnet', value: args[i + 1].toLowerCase() }, `argv[${i + 2}]`);
      const m = /^-[nf](.+)$/.exec(args[i]);
      if (m) add({ kind: 'qnet', value: m[1].toLowerCase() }, `argv[${i + 1}]`);
    }
  }

  if (isNet) {
    // Every positional of a packet-sending tool is a target candidate.
    // Flag values are positional too: a value that is not numeric and not a
    // recognizable target is refused (fail closed) rather than guessed at.
    args.forEach((arg, i) => {
      if (arg.startsWith('-') || NUMERIC.test(arg)) return;
      const t = classify(arg);
      if (!t || t.kind === 'unparseable') problems.push(`argv[${i + 1}]: "${arg}" is not a recognizable target for a network tool`);
      else add(t, `argv[${i + 1}]`);
    });
  }
  return { targets, problems };
}

/** Self set: the target node itself is always in scope. */
function selfSet(catalog) {
  const meta = (catalog && catalog.meta) || {};
  const net = (catalog && catalog.network) || {};
  const hosts = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost']);
  if (meta.hostname) { hosts.add(String(meta.hostname).toLowerCase()); hosts.add(String(meta.hostname).toLowerCase().split('.')[0]); }
  const ips = new Set(['0.0.0.0', ...(net.interface_ips || [])]);
  return { hosts, ips, v6: new Set(['::1', '::']), loop: parseCidr('127.0.0.0/8') };
}

/** Engagements — HMAC-signed by the operator key; agent seats cannot mint them. */
function signEngagement(e, key) {
  const { sig, ...body } = e;
  return crypto.createHmac('sha256', key).update(canonical(body)).digest('hex');
}

function loadEngagements(file, key, now = Date.now()) {
  const out = { engagements: [], rejected: [], error: null };
  let doc;
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {
    out.error = e.code === 'ENOENT' ? 'no engagements file' : `engagements file unreadable: ${e.message}`;
    return out; // fail closed: no engagements
  }
  if (!doc || !Array.isArray(doc.engagements)) { out.error = 'engagements file malformed'; return out; }
  if (!key) { out.error = 'no operator key: engagements cannot be verified'; out.rejected = doc.engagements.map((e) => ({ id: e && e.id, reason: 'unverifiable' })); return out; }
  for (const e of doc.engagements) {
    const id = e && e.id;
    if (!e || typeof e.id !== 'string' || !Array.isArray(e.targets) || typeof e.sig !== 'string') { out.rejected.push({ id, reason: 'malformed' }); continue; }
    const want = signEngagement(e, key);
    const ok = want.length === e.sig.length && crypto.timingSafeEqual(Buffer.from(want), Buffer.from(e.sig));
    if (!ok) { out.rejected.push({ id, reason: 'bad signature' }); continue; }
    if (e.expires_at && Date.parse(e.expires_at) <= now) { out.rejected.push({ id, reason: 'expired' }); continue; }
    out.engagements.push(e);
  }
  return out;
}

/** Decide one target. Returns {in_scope, reason, engagement?}. */
function decide(t, self, engagements) {
  if (t.kind === 'unparseable') return { in_scope: false, reason: 'unparseable target' };
  if (t.kind === 'ipv4') {
    if (self.ips.has(t.value) || inCidr(t.value, self.loop)) return { in_scope: true, reason: 'self' };
    for (const e of engagements) for (const s of e.targets) {
      if (s === t.value) return { in_scope: true, reason: 'engagement exact', engagement: e.id };
      const c = parseCidr(s);
      if (c && inCidr(t.value, c)) return { in_scope: true, reason: `engagement CIDR ${c.text}`, engagement: e.id };
    }
    return { in_scope: false, reason: 'no verified engagement covers this address' };
  }
  if (t.kind === 'cidr') {
    if (t.cidr.bits === 32 && (self.ips.has(t.value.split('/')[0]) || inCidr(t.value.split('/')[0], self.loop))) return { in_scope: true, reason: 'self' };
    for (const e of engagements) for (const s of e.targets) { const c = parseCidr(s); if (c && c.text === t.value) return { in_scope: true, reason: 'engagement exact CIDR', engagement: e.id }; }
    return { in_scope: false, reason: 'a CIDR target needs the exact CIDR named in a verified engagement' };
  }
  if (t.kind === 'ipv6') {
    if (self.v6.has(t.value)) return { in_scope: true, reason: 'self' };
    for (const e of engagements) if (e.targets.map((x) => String(x).toLowerCase()).includes(t.value)) return { in_scope: true, reason: 'engagement exact', engagement: e.id };
    return { in_scope: false, reason: 'no verified engagement names this address' };
  }
  if (t.kind === 'host' || t.kind === 'qnet') {
    if (self.hosts.has(t.value)) return { in_scope: true, reason: 'self' };
    const want = t.kind === 'qnet' ? [`qnet:${t.value}`] : [t.value];
    for (const e of engagements) if (e.targets.map((x) => String(x).toLowerCase()).some((x) => want.includes(x))) return { in_scope: true, reason: 'engagement exact', engagement: e.id };
    return { in_scope: false, reason: t.kind === 'qnet' ? 'Qnet node not named in a verified engagement (name it as qnet:<node>)' : 'hostname not named in a verified engagement (never resolved)' };
  }
  return { in_scope: false, reason: 'unknown target kind' };
}

/** Full scope decision for one call. */
function check(toolName, args, catalog, engagementsDoc) {
  const { targets, problems } = extractTargets(toolName, args);
  const self = selfSet(catalog);
  const decisions = targets.map((t) => ({ target: t.value, kind: t.kind, source: t.source, ...decide(t, self, engagementsDoc.engagements) }));
  const denied = decisions.filter((d) => !d.in_scope);
  const allowed = problems.length === 0 && denied.length === 0;
  return {
    allowed,
    decisions,
    problems,
    reason: allowed ? null : (problems[0] || `${denied[0].target}: ${denied[0].reason}`),
  };
}

/** Validate one engagement target as the operator typed it: IPv4, exact CIDR, IPv6, hostname, or qnet:<node>. */
function validTarget(t) {
  if (typeof t !== 'string' || !t.trim()) return false;
  if (t.startsWith('qnet:')) return /^qnet:[A-Za-z0-9._-]+$/.test(t);
  const c = classify(t.trim());
  return !!c && c.kind !== 'unparseable' && c.value.toLowerCase() === t.trim().toLowerCase().replace(/\.$/, '');
}

function readDoc(file) { try { const d = JSON.parse(fs.readFileSync(file, 'utf8')); return d && Array.isArray(d.engagements) ? d : { engagements: [] }; } catch { return { engagements: [] }; } }

/** Sign and store an engagement with the operator key (the only way one becomes verified). Replaces one with the same id. */
function addEngagement(file, key, { id, targets, hours = 24, operator = 'operator' }) {
  if (!key) throw new Error('no operator key: engagements cannot be signed on this box');
  if (typeof id !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(id)) throw new Error('id must be 1-64 letters, digits, dot, dash or underscore');
  if (!Array.isArray(targets) || !targets.length || targets.length > 64) throw new Error('give 1 to 64 targets');
  const bad = targets.filter((t) => !validTarget(t));
  if (bad.length) throw new Error(`not a valid target: ${bad.join(', ')} (use an IPv4/IPv6 address, an exact CIDR, a hostname, or qnet:<node>)`);
  const h = Number(hours);
  if (!(h > 0 && h <= 24 * 30)) throw new Error('hours must be between 0 and 720');
  const e = { id, targets: targets.map((t) => t.trim()), operator, issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + h * 3600e3).toISOString() };
  e.sig = signEngagement(e, key);
  const doc = readDoc(file);
  doc.engagements = doc.engagements.filter((x) => x && x.id !== id).concat([e]);
  fs.writeFileSync(file, JSON.stringify(doc, null, 2));
  return e;
}

/** Remove an engagement by id. Returns whether one was removed. */
function revokeEngagement(file, id) {
  const doc = readDoc(file);
  const before = doc.engagements.length;
  doc.engagements = doc.engagements.filter((x) => x && x.id !== id);
  fs.writeFileSync(file, JSON.stringify(doc, null, 2));
  return doc.engagements.length < before;
}

module.exports = { extractTargets, check, loadEngagements, signEngagement, addEngagement, revokeEngagement, validTarget, classify, parseCidr, inCidr, selfSet };
