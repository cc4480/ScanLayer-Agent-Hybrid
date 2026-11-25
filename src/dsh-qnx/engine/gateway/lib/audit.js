'use strict';
// Hash-chained audit log. Every call, every denial, every run start/end is one
// JSON line. hash = sha256(prev_hash + "\n" + canonical(entry without hash)).
// The first entry chains from GENESIS. verifyChain() recomputes every link; a
// one-byte edit anywhere breaks it at that line. seal() signs the head with
// the gateway's ed25519 key so a reviewer can check the chain cold.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { canonical, sha256 } = require('./canon');

const GENESIS = '0'.repeat(64);

function entryHash(prev, entry) {
  const { hash, ...body } = entry;
  return sha256(prev + '\n' + canonical(body));
}

class Audit extends EventEmitter {
  constructor(file) {
    super();
    this.file = file;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tail = Audit.readAll(file);
    this.seq = tail.length;
    this.head = tail.length ? tail[tail.length - 1].hash : GENESIS;
    // Refuse to extend a broken chain: appending to tampered history would launder it.
    const v = verifyChain(file);
    if (!v.ok) throw new Error(`audit chain broken at line ${v.bad_line}: ${v.reason} — refusing to start (move the log aside to investigate)`);
  }

  static readAll(file) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { return []; }
    return text.split('\n').filter(Boolean).map((l) => JSON.parse(l));
  }

  append(fields) {
    const entry = { seq: this.seq + 1, ts: new Date().toISOString(), ...fields, prev: this.head };
    entry.hash = entryHash(this.head, entry);
    fs.appendFileSync(this.file, JSON.stringify(entry) + '\n', { mode: 0o600 });
    this.seq = entry.seq;
    this.head = entry.hash;
    this.emit('entry', entry);
    return entry;
  }

  since(seq = 0, limit = 500) {
    return Audit.readAll(this.file).filter((e) => e.seq > seq).slice(0, limit);
  }

  findByHash(h) { return Audit.readAll(this.file).find((e) => e.hash === h) || null; }
}

function verifyChain(file) {
  let lines;
  try { lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean); } catch (e) {
    if (e.code === 'ENOENT') return { ok: true, count: 0, head: GENESIS };
    return { ok: false, count: 0, bad_line: 0, reason: e.message };
  }
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let e;
    try { e = JSON.parse(lines[i]); } catch { return { ok: false, count: i, bad_line: i + 1, reason: 'not JSON' }; }
    if (e.prev !== prev) return { ok: false, count: i, bad_line: i + 1, reason: 'prev link mismatch' };
    if (e.seq !== i + 1) return { ok: false, count: i, bad_line: i + 1, reason: 'sequence gap' };
    if (entryHash(prev, e) !== e.hash) return { ok: false, count: i, bad_line: i + 1, reason: 'hash mismatch (entry altered)' };
    prev = e.hash;
  }
  return { ok: true, count: lines.length, head: prev };
}

// ---------- ed25519 signing key (seal + reports) ----------
function loadOrCreateKey(dir) {
  const priv = path.join(dir, 'signing-ed25519.pem');
  if (!fs.existsSync(priv)) {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(priv, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(priv));
  const publicKey = crypto.createPublicKey(privateKey);
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    privateKey, publicKey, pubPem,
    keyId: sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(0, 16),
    sign: (obj) => crypto.sign(null, Buffer.from(canonical(obj)), privateKey).toString('base64'),
    verify: (obj, sig) => crypto.verify(null, Buffer.from(canonical(obj)), publicKey, Buffer.from(sig, 'base64')),
  };
}

function verifySigned(doc, pubPem) {
  const { signature, ...body } = doc;
  if (!signature || !signature.sig) return false;
  const pk = crypto.createPublicKey(pubPem);
  return crypto.verify(null, Buffer.from(canonical(body)), pk, Buffer.from(signature.sig, 'base64'));
}

module.exports = { Audit, verifyChain, entryHash, GENESIS, loadOrCreateKey, verifySigned };
