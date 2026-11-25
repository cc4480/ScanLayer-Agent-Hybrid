'use strict';
// Canonical JSON: object keys sorted recursively, no whitespace. Every hash and
// signature in the system is computed over this form, so any verifier in any
// language can recompute it.
function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}
const sha256 = (s) => require('crypto').createHash('sha256').update(s).digest('hex');
module.exports = { canonical, sha256 };
