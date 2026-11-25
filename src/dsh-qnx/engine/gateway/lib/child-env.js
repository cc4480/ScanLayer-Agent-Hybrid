'use strict';
// Environment for the engine's child processes (the sandbox child, Agent Smith). On POSIX they get an empty
// environment: nothing of the host leaks in. Windows cannot run a process with nothing: without SystemRoot, Winsock
// cannot open a socket (Agent Smith reaches the engine over 127.0.0.1), so only the variables the OS itself needs pass.
const WINDOWS_ESSENTIALS = ['SystemRoot', 'SYSTEMROOT', 'windir', 'WINDIR', 'SystemDrive', 'TEMP', 'TMP', 'ComSpec'];

function childEnv(platform = process.platform, env = process.env) {
  if (platform !== 'win32') return {};
  const out = {};
  for (const k of WINDOWS_ESSENTIALS) if (env[k] !== undefined) out[k] = env[k];
  return out;
}

module.exports = { childEnv };
