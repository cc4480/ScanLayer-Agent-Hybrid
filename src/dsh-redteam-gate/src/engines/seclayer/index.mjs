// Native SecLayer red-team modules. Each exports name, owaspCategory and run(target, opts, fetchFn).
// Every request goes through the verified-scope gate in src/scope.mjs. Deferred: weak session token,
// blind SSRF (needs an out-of-band collaborator service, which is out of scope for this native port).

import * as reflectedXss from './reflectedXss.mjs'
import * as sqlInjection from './sqlInjection.mjs'
import * as ssrf from './ssrf.mjs'
import * as commandInjection from './commandInjection.mjs'

export { ScopeDeniedError } from './gate.mjs'

export const REDTEAM_MODULES = Object.freeze([reflectedXss, sqlInjection, ssrf, commandInjection])
