// Glue for the verbatim secscan-src copy. Lives OUTSIDE secscan-src/ so the copied files stay byte-identical.
//
// gatedFetch() wraps an injected fetch function with the verified-scope gate (src/scope.mjs decideScope).
// Every request is checked first. A denied target throws before fetchFn is called, so zero packets are sent.
// The gate's ACTIVE_TOOLS policy is applied by naming the probe with an active tool name ('nuclei' by default).
import { decideScope } from '../../scope.mjs';

/**
 * @param {{ gate: { isVerified: (domain: string) => Promise<boolean> }, fetchFn: (url: string, opts?: object) => Promise<any>, toolName?: string }} cfg
 * @returns {(url: string, opts?: object) => Promise<any>}
 */
export function gatedFetch({ gate, fetchFn, toolName = 'nuclei' }) {
  if (!gate || typeof gate.isVerified !== 'function') throw new TypeError('gatedFetch: a scope gate with isVerified() is required');
  if (typeof fetchFn !== 'function') throw new TypeError('gatedFetch: fetchFn must be a function');
  return async function gated(url, opts) {
    const decision = await decideScope({ toolName, arguments: { target: String(url) } }, gate);
    if (decision.kind !== 'allow') {
      const err = new Error(`scope gate refused ${String(url)}: ${decision.reason}`);
      err.code = 'SCOPE_DENIED';
      throw err;
    }
    return fetchFn(url, opts);
  };
}
