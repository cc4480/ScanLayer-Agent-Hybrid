// Which optional tools can actually run on this machine. A tool whose program is missing is not
// registered, so the agent never spends a turn calling something that can only fail. The scope gate
// (scope.mjs) is unaffected: a shell command naming one of these programs is still checked.
import fs from 'node:fs'
import path from 'node:path'
import { BINARIES, PERL_EXE, NIKTO_SCRIPT } from './tools.mjs'
import { MSF_RUBY, MSF_SCRIPT } from './engines/metasploit/msf.mjs'
import { resolvePcAgentDir } from './engines/alterego/bridge.mjs'

/** Files each optional tool needs, by tool name. The AlterEgo entry covers every ae_ tool. */
export function toolRequirements(env = process.env) {
  return {
    nmap: [BINARIES.nmap],
    nuclei: [BINARIES.nuclei],
    ffuf: [BINARIES.ffuf],
    gobuster: [BINARIES.gobuster],
    sqlmap: [BINARIES.sqlmap],
    john: [BINARIES.john],
    // nikto runs its Perl script directly (see niktoLaunch), not the batch file.
    nikto: [PERL_EXE, NIKTO_SCRIPT],
    msfconsole: [MSF_RUBY, MSF_SCRIPT],
    alterego: [path.join(resolvePcAgentDir(env), 'tool_wrappers.py')],
  }
}

/**
 * Split the optional tools into those that can run and those that cannot.
 * @param {{exists?: (p: string) => boolean, env?: NodeJS.ProcessEnv}} [opts]
 * @returns {{available: Set<string>, missing: Record<string, string[]>}}
 */
export function checkAvailability({ exists = fs.existsSync, env = process.env } = {}) {
  const available = new Set()
  const missing = {}
  for (const [name, files] of Object.entries(toolRequirements(env))) {
    const absent = files.filter((f) => !exists(f))
    if (absent.length === 0) available.add(name)
    else missing[name] = absent
  }
  return { available, missing }
}
