// AlterEgo native read-only allowlist.
// Only tools listed here may be registered as native tools. Everything else in the
// AlterEgo catalog (109 tools, see inventory.md) is deferred until the owner approves it.
// Every entry here must be risk 'read' in inventory.md; the inventory test enforces that.

export const ALLOWLIST_VERSION = 1;

const int = (description, extra = {}) => ({ type: 'integer', description, ...extra });
const str = (description) => ({ type: 'string', description });

export const READ_ONLY_ALLOWLIST = Object.freeze({
  screenshot: {
    description: 'Capture the primary monitor as a PNG (base64). Read-only.',
    parameters: {
      type: 'object',
      properties: {
        scale: { type: 'number', minimum: 0.05, maximum: 1, description: 'Scale factor (default 1.0).' },
        region: {
          type: 'object',
          description: 'Optional crop region in screen pixels.',
          properties: { x: int('left'), y: int('top'), width: int('width'), height: int('height') },
          required: ['x', 'y', 'width', 'height'],
          additionalProperties: false,
        },
      },
      additionalProperties: false,
    },
  },
  list_windows: {
    description: 'List visible windows (handle, pid, title). Paginated. Read-only.',
    parameters: {
      type: 'object',
      properties: { offset: int('Start offset.', { minimum: 0 }), limit: int('Max items (0 = server default).', { minimum: 0 }) },
      additionalProperties: false,
    },
  },
  active_window: {
    description: 'Foreground window: handle, title, pid, process. Read-only.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
  },
  system_info: {
    description: 'OS, host, user, CPU and memory summary. Read-only.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
  },
  list_processes: {
    description: 'Running processes (pid and executable). Read-only; does not kill anything.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
  },
  list_dir: {
    description: 'List a directory inside the user profile. Read-only.',
    parameters: {
      type: 'object',
      properties: {
        path: str('Directory path (default: profile root).'),
        offset: int('Start offset.', { minimum: 0 }),
        limit: int('Max items (0 = server default).', { minimum: 0 }),
      },
      additionalProperties: false,
    },
  },
  read_file: {
    description: 'Read a UTF-8 text file (max 1 MB) inside the user profile. Read-only.',
    parameters: {
      type: 'object',
      properties: { path: str('File path inside the user profile.') },
      required: ['path'],
      additionalProperties: false,
    },
  },
  read_file_range: {
    description: 'Read a 1-indexed line range of a profile file. Read-only.',
    parameters: {
      type: 'object',
      properties: {
        path: str('File path inside the user profile.'),
        start_line: int('First line (1-indexed).', { minimum: 1 }),
        end_line: int('Last line (0 = start + 50).', { minimum: 0 }),
      },
      required: ['path', 'start_line'],
      additionalProperties: false,
    },
  },
  search_files: {
    description: 'Regex content search under a profile directory. Read-only.',
    parameters: {
      type: 'object',
      properties: {
        pattern: str('Regex pattern.'),
        path: str('Directory to search.'),
        file_pattern: str('Filename glob (default "*").'),
        max_results: int('Max results.', { minimum: 1 }),
        context: int('Context lines.', { minimum: 0 }),
        case_insensitive: { type: 'boolean', description: 'Ignore case.' },
        offset: int('Start offset.', { minimum: 0 }),
      },
      required: ['pattern', 'path'],
      additionalProperties: false,
    },
  },
  search_filenames: {
    description: 'Find files by name glob under a profile directory. Read-only.',
    parameters: {
      type: 'object',
      properties: {
        pattern: str('Filename glob.'),
        path: str('Directory to search.'),
        max_results: int('Max results.', { minimum: 1 }),
        sort_by: str('Sort key (default "name").'),
        offset: int('Start offset.', { minimum: 0 }),
      },
      required: ['pattern', 'path'],
      additionalProperties: false,
    },
  },
});

export const ALLOWLISTED_TOOLS = Object.freeze(Object.keys(READ_ONLY_ALLOWLIST));

// Read-only or sensitive tools that exist in AlterEgo but are not registered in this pass.
// Each has a reason; the owner decides whether to promote any of them.
export const DEFERRED = Object.freeze({
  desktop_state: 'read-only but bundles a screenshot and UI tree; promote after screenshot review',
  uia_find: 'read-only UI tree of other apps; not needed for first pass',
  file_info: 'read-only but not profile-restricted (any absolute path); owner to decide',
  wait_for: 'read-only poll but can block for timeout_s; owner to decide',
  idle_seconds: 'read-only, low value for first pass',
  clipboard_get: 'read-only but clipboard often holds secrets; owner approval required',
  memory_recall: 'read-only search of personal transcripts archive; owner approval required',
  record_audio: 'microphone capture; always_ask; owner approval required',
  cdp_targets: 'read-only but attaches to browser debug sessions',
  cdp_snapshot: 'read-only but depends on a CDP session that must be launched first',
  cdp_readback: 'read-only but depends on a CDP session',
  browser_snapshot: 'read-only but attaches to a live Edge tab',
  exec_status: 'read-only job poll; only useful with exec_background (deferred)',
  job_status: 'read-only job poll; job layer deferred',
  job_result: 'read-only job result; job layer deferred',
  doctor: 'health check; not needed for first pass',
  doctor_jobs: 'health check; not needed for first pass',
  query_events: 'reads the operation log; owner approval (contains call history)',
  replay_session: 'reads the operation log; owner approval',
  task_status: 'read-only task verification; deferred',
  list_elicitations: 'read-only; deferred',
  list_watches: 'read-only; deferred',
  poll_changes: 'read-only change journal; deferred',
  dashboard: 'read-only status widget; deferred',
  tool_finder: 'catalog search; deferred',
  search_tools: 'catalog search; deferred',
  complete_arg: 'reads live window and path state; deferred',
  macro_list: 'read-only macro list; deferred',
  supervisor_status: 'read-only supervisor state; deferred',
  arbitrate_tool: 'scoring helper; no PC effect but no profile; deferred',
  shell_exec: 'EXEC: arbitrary cmd.exe. Excluded from this pass. Owner must approve separately.',
  shell_pwsh: 'EXEC: arbitrary PowerShell. Excluded from this pass. Owner must approve separately.',
  exec_background: 'EXEC: background shell. Excluded from this pass. Owner must approve separately.',
  exec: 'EXEC: multi-op shell wrapper. Excluded from this pass. Owner must approve separately.',
  submit_job: 'EXEC: dispatches any tool asynchronously. Excluded from this pass.',
  batch: 'EXEC: runs up to 20 tool calls. Excluded from this pass.',
  macro_replay: 'EXEC: replays recorded tool calls. Excluded from this pass.',
  power: 'EXEC: lock, sleep, restart or shut down the PC. Excluded from this pass.',
  kill_process: 'EXEC/WRITE: terminates processes. Excluded from this pass.',
  process: 'EXEC/WRITE: process list or kill. Excluded from this pass.',
  server_reload: 'EXEC: restarts the bridge server. Excluded from this pass.',
  hot_reload: 'EXEC: reloads bridge behavior. Excluded from this pass.',
});

export function isAllowlisted(name) {
  return typeof name === 'string' && Object.prototype.hasOwnProperty.call(READ_ONLY_ALLOWLIST, name);
}

/** Minimal JSON-schema-subset validation: type, required, enum-free, unknown keys rejected. */
export function validateArgs(name, args) {
  const spec = READ_ONLY_ALLOWLIST[name];
  if (!spec) return { ok: false, error: `tool not allowlisted: ${name}` };
  const schema = spec.parameters;
  if (args === undefined || args === null) args = {};
  if (typeof args !== 'object' || Array.isArray(args)) return { ok: false, error: 'args must be an object' };
  for (const key of Object.keys(args)) {
    if (!(key in schema.properties)) return { ok: false, error: `unknown argument: ${key}` };
  }
  for (const key of schema.required ?? []) {
    if (!(key in args)) return { ok: false, error: `missing required argument: ${key}` };
  }
  for (const [key, value] of Object.entries(args)) {
    const prop = schema.properties[key];
    const err = checkValue(prop, value, key);
    if (err) return { ok: false, error: err };
  }
  return { ok: true, args };
}

function checkValue(prop, value, key) {
  if (prop.type === 'string' && typeof value !== 'string') return `${key} must be a string`;
  if (prop.type === 'boolean' && typeof value !== 'boolean') return `${key} must be a boolean`;
  if (prop.type === 'number' || prop.type === 'integer') {
    if (typeof value !== 'number' || !Number.isFinite(value)) return `${key} must be a number`;
    if (prop.type === 'integer' && !Number.isInteger(value)) return `${key} must be an integer`;
    if (prop.minimum !== undefined && value < prop.minimum) return `${key} must be >= ${prop.minimum}`;
    if (prop.maximum !== undefined && value > prop.maximum) return `${key} must be <= ${prop.maximum}`;
  }
  if (prop.type === 'object') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return `${key} must be an object`;
    for (const k of Object.keys(value)) {
      if (!(k in prop.properties)) return `unknown argument: ${key}.${k}`;
    }
    for (const k of prop.required ?? []) {
      if (!(k in value)) return `missing required argument: ${key}.${k}`;
    }
    for (const [k, v] of Object.entries(value)) {
      const err = checkValue(prop.properties[k], v, `${key}.${k}`);
      if (err) return err;
    }
  }
  return null;
}
