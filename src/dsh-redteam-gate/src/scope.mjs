// Verified-scope gate for NATIVE active tools (nmap, nuclei, ffuf, gobuster, nikto, sqlmap,
// Metasploit) and for shell commands that invoke them.
//
// Policy (fail closed):
//   - Lab hosts (loopback only: 127.0.0.1, localhost, ::1) are allowed. This is the documented
//     lab exception (owner decision 2026-11-21): no real target is reachable under it.
//   - Any other domain must be verified by the SecScan server (injected `isVerified`, which must
//     fail closed itself). Raw IPs other than loopback are never verifiable and are denied.
//   - An active tool with no discoverable target is denied.
//   - A shell command that invokes an active tool is checked on EVERY host it names, so an extra
//     `curl https://evil.example` in the same command is also denied.
//   - Everything else (passive tools, file reads, ordinary shell) is allowed.
//
// There is no bypass: no environment variable, config value, or session flag loosens this. The
// former SCAN_SKIP_OWNERSHIP_GATE escape hatch was removed (owner decision 2026-11-25) because an
// inherited env var could silently authorize active probes against domains nobody had verified.

export const LAB_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

export const ACTIVE_TOOLS = new Set([
  'nmap', 'nuclei', 'ffuf', 'gobuster', 'nikto', 'sqlmap', 'msfconsole', 'msfrpcd', 'msfvenom',
  'secscan_fetch', 'seclayer_probe', 'webapp_scan', 'seclayer_scan', 'generate_scan_report',
]);

// Flags that read targets from a file or list; they can hide hosts from the gate, so they are refused.
const FILE_OF_TARGETS_RE = /^(-l|-il|--input-file|--iL|--list|-m|-r|--targets-file)(=.*)?$/i

const SHELL_TOOLS = new Set(['bash', 'shell', 'run_command', 'powershell', 'cmd']);
const TARGET_KEYS = new Set(['target', 'targets', 'url', 'urls', 'host', 'hosts', 'ip', 'ips', 'address', 'domain', 'site', 'rhosts', 'rhost']);

const URL_RE = /\bhttps?:\/\/([^\s/'"`;|&)<>]+)/gi;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_RE = /\[?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

/** Base tool name, tolerating the MCP namespace (mcp__server__tool). */
export function baseName(toolName) {
  const parts = String(toolName).split('__');
  return (parts[parts.length - 1] ?? '').toLowerCase();
}

/** Strip a trailing :port, brackets, and a trailing dot. */
function normalizeHost(raw) {
  let h = String(raw).trim().toLowerCase();
  if (h.startsWith('[') && h.includes(']')) h = h.slice(1, h.indexOf(']'));
  else if (h.split(':').length === 2) h = h.split(':')[0]; // host:port (not IPv6)
  return h.replace(/\.$/, '');
}

/**
 * Every host-like token named in a string: URL hosts, IPv4 addresses, IPv6 literals and domains.
 * @param {string} text
 * @returns {string[]} normalized hosts, deduplicated
 */
export function extractHosts(text) {
  const found = new Set();
  for (const m of text.matchAll(URL_RE)) found.add(normalizeHost(m[1]));
  for (const m of text.matchAll(IPV4_RE)) found.add(m[0]);
  for (const m of text.matchAll(IPV6_RE)) {
    const v = m[0].replace(/^\[|\]$/g, '');
    if (v.includes(':')) found.add(normalizeHost(`[${v}]`));
  }
  for (const m of text.matchAll(DOMAIN_RE)) found.add(m[0].toLowerCase());
  return [...found].filter(Boolean);
}

/** Collect every string value from an argument object, recursively. */
function collectStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => collectStrings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collectStrings(v, out));
  return out;
}

/** Targets named by structured arguments (target-like keys first, then any string value). */
function targetsFromArgs(args) {
  const named = [];
  for (const [k, v] of Object.entries(args ?? {})) {
    if (TARGET_KEYS.has(k.toLowerCase())) named.push(...collectStrings(v));
  }
  const source = named.length > 0 ? named : collectStrings(args);
  return [...new Set(source.flatMap((s) => extractHosts(s)))];
}

function isLoopback(host) {
  return LAB_HOSTS.has(host);
}

function looksLikeIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

/**
 * Decide whether one tool call may run.
 * @param {{toolName: string, arguments?: Record<string, unknown>}} exec
 * @param {{isVerified: (domain: string) => Promise<boolean>}} gate - must fail closed
 * @returns {Promise<{kind: 'allow'} | {kind: 'deny', reason: string}>}
 */
export async function decideScope(exec, gate) {
  const base = baseName(exec.toolName);
  const args = exec.arguments ?? {};

  let hosts;
  if (SHELL_TOOLS.has(base)) {
    const command = collectStrings(args).join(' ');
    const words = command.toLowerCase().split(/[^a-z0-9_-]+/);
    if (!words.some((w) => ACTIVE_TOOLS.has(w))) return { kind: 'allow' };
    hosts = extractHosts(command);
    if (hosts.length === 0) {
      return { kind: 'deny', reason: 'active tool invoked from shell with no target named; scope cannot be verified' };
    }
  } else if (ACTIVE_TOOLS.has(base)) {
    // Target-keyed values AND every other string argument (flags included) are checked, so a host or
    // file-of-targets smuggled through `flags` is seen by the gate too.
    const allStrings = collectStrings(args)
    const flagTokens = allStrings.flatMap((s) => s.split(/\s+/))
    const fileOfTargets = flagTokens.find((t) => FILE_OF_TARGETS_RE.test(t))
    if (fileOfTargets !== undefined) {
      return { kind: 'deny', reason: `${base}: flag ${fileOfTargets} reads a file of targets; name each target explicitly` }
    }
    hosts = [...new Set([...targetsFromArgs(args), ...allStrings.flatMap((s) => extractHosts(s))])]
    if (hosts.length === 0) {
      return { kind: 'deny', reason: `${base}: no target named; scope cannot be verified` };
    }
  } else {
    return { kind: 'allow' };
  }

  for (const host of hosts) {
    if (isLoopback(host)) continue;
    if (looksLikeIp(host)) {
      return { kind: 'deny', reason: `${host} is not a lab host and IP targets cannot be ownership-verified` };
    }
    let verified = false;
    try {
      verified = (await gate.isVerified(host)) === true;
    } catch {
      verified = false;
    }
    if (!verified) {
      return { kind: 'deny', reason: `${host} is not a lab host and is not verified in SecScan; zero packets sent` };
    }
  }
  return { kind: 'allow' };
}
