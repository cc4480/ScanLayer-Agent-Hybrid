// Missing-rate-limit probe for OTP / 2FA verification endpoints (AGGRESSIVE tier).
//
// UNLIKE every other probe in this codebase, this one CANNOT positively prove
// its finding: it observes the ABSENCE of a control, and you can never prove a
// negative from a bounded number of samples ("no throttle in N tries" ≠ "no
// throttle exists"). It is therefore reported at LOW confidence (needs
// verification) and MEDIUM severity, never PROVEN — and medium severity is
// deliberate: an unconfirmed claim must never be able to label a site HIGH RISK.
// It stays as accurate and low-invasive as possible:
//   * A bounded burst of wrong codes (BURST attempts), never a real brute-force.
//     The burst MUST clear the thresholds real limiters use. An earlier BURST of
//     6 reported "no limiter" on an endpoint whose limiter was max=6, and a
//     BURST of 12 did the same on another whose limiter was max=20 — a fixed
//     burst below an unknown threshold always looks like an absence. 30 covers
//     the whole common 3-30 band with margin, and the loop aborts on the first
//     throttle, so a limited endpoint still costs only one request past its
//     threshold.
//   * A correctly-limited endpoint is detected reliably: express-rate-limit and
//     most gateways emit RateLimit-*/Retry-After headers (often on the FIRST
//     response) and/or a 429 — any of which means "throttled" → no finding.
//     The burst aborts the moment a throttle appears, so a limited endpoint
//     costs at most one request past its threshold.
//   * Precondition: the endpoint must consistently REJECT wrong codes with a 4xx
//     (so it really is a verify endpoint processing our attempts); a 404 or a
//     2xx-accepts-anything response is skipped, not flagged.
//   * A 400 that says a REQUEST FIELD is missing ("Enter the email and the
//     6-digit code") is a validation rejection, not a credential rejection: our
//     attempt never reached the code comparison, so it says nothing about
//     throttling. Those candidates are skipped rather than flagged. The probe
//     therefore sends the field names common verify endpoints require (email,
//     phoneNumber, code, otp) so it reaches the comparison stage wherever it can.
// Residual reasons it stays LOW confidence: a limiter that emits no headers and
// whose threshold exceeds the burst would be missed, and a real OTP endpoint may
// reject our attempts for lack of a pending-session context (looking like "no
// throttle"). Absence-of-limit is inherently a heuristic.
import { safeFetch } from "./ssrf.js";
import type { RedTeamFinding } from "./scanTypes.js";

const BURST = 30;
const VERIFY_PATHS = [
  "/api/auth/verify-sms", "/api/auth/verify-otp", "/api/verify-otp", "/api/verify-sms",
  "/api/2fa/verify", "/api/mfa/verify", "/api/auth/verify-code", "/api/verify-code",
  "/api/otp/verify", "/verify-otp", "/api/auth/2fa/verify",
];
const VERIFY_HINT = /(verify|otp|2fa|mfa|totp)/i;
const THROTTLE_HEADER = /^(ratelimit-|x-ratelimit-|retry-after)/i;
const THROTTLE_BODY = /too many|rate.?limit|try again (?:later|in)|slow down|locked|throttl/i;
// A 400 shaped like "a request field is missing/required" — the attempt never
// reached the code comparison, so it is not evidence about throttling.
const REQUEST_SHAPE = /\b(?:enter|provide|supply|required|missing|must|needs?)\b[^.!?]{0,60}\b(?:e-?mail|phone|code|otp|token|field|parameter)\b/i;
const REJECTION = new Set([400, 401, 403, 422]);

// Field names the common verify endpoints require. Sending all of them costs
// nothing and lets a real endpoint reach its code check instead of bouncing on
// validation (which looks exactly like "no throttle").
const PROBE_EMAIL = "scanner-probe@example.com";
const PROBE_PHONE = "+15555550100";

const bodyFor = (n: number) => {
  const code = String(100000 + n); // a distinct, wrong 6-digit code per attempt
  return JSON.stringify({ email: PROBE_EMAIL, phoneNumber: PROBE_PHONE, code, otp: code });
};

type Attempt = { status: number; throttled: boolean; text: string };

async function postAttempt(url: string, headers: Record<string, string>, n: number): Promise<Attempt> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: bodyFor(n),
      signal: ctl.signal,
    });
    const text = await res.text().catch(() => "");
    let headerThrottle = false;
    res.headers.forEach((_v, k) => { if (THROTTLE_HEADER.test(k)) headerThrottle = true; });
    const throttled = res.status === 429 || headerThrottle || THROTTLE_BODY.test(text);
    return { status: res.status, throttled, text };
  } finally {
    clearTimeout(id);
  }
}

/** True when a 400 says our REQUEST was malformed — not that the code was wrong. */
function isMalformedRequest(a: Attempt): boolean {
  return a.status === 400 && REQUEST_SHAPE.test(a.text);
}

export async function probeAuthRateLimit(
  rootUrl: string,
  postUrls: string[],
  headers: Record<string, string>,
): Promise<RedTeamFinding | null> {
  const base = rootUrl.replace(/\/+$/, "");
  const candidates = [
    ...new Set([
      ...VERIFY_PATHS.map((p) => `${base}${p}`),
      ...postUrls.filter((u) => VERIFY_HINT.test(u)),
    ]),
  ];

  for (const url of candidates) {
    // First attempt establishes the precondition: a real verify endpoint that
    // REJECTS a wrong code (4xx) and isn't already throttling.
    let first: Attempt;
    try { first = await postAttempt(url, headers, 0); } catch { continue; }
    if (first.throttled) continue;          // already rate-limited → safe, no finding
    if (!REJECTION.has(first.status)) continue; // 404 (no endpoint) or 2xx (accepts anything) → not a testable verify endpoint
    if (isMalformedRequest(first)) continue;    // rejected for a missing field → never compared a code, says nothing about throttling

    // Fire the rest of the bounded burst; bail the moment ANY throttle appears.
    let throttledAt = 0;
    let consistent = true;
    for (let n = 1; n < BURST; n++) {
      let r: Attempt;
      try { r = await postAttempt(url, headers, n); } catch { consistent = false; break; }
      if (r.throttled) { throttledAt = n + 1; break; }
      if (!REJECTION.has(r.status)) { consistent = false; break; } // response shape changed → ambiguous, don't flag
    }
    if (throttledAt > 0 || !consistent) continue; // throttled or ambiguous → no finding

    // All BURST wrong-code attempts were rejected identically with NO throttling
    // signal (no 429, no RateLimit-*/Retry-After header, no throttle text).
    return {
      testName: "No Rate Limiting on Authentication-Code Verification",
      payload: `${BURST}× wrong-code POST to ${url}`,
      // LOW severity + LOW confidence is deliberate: this is an observation of an
      // absent control, not a proven vulnerability. Most real verify endpoints
      // cap attempts PER CODE rather than per IP — those answer every guess with
      // the same 401 and are invisible to a black-box burst, so "no throttle in
      // 30 tries" is genuinely weak evidence. The finding is reported so a human
      // can look, and is scored as a low-risk hygiene note.
      severity: "low",
      confidence: "low", // observational (absence of a control) — needs manual verification, never PROVEN
      description:
        `A verification endpoint (${url}) rejected ${BURST} rapid wrong-code attempts in a row without any throttling signal — no 429, no RateLimit-*/Retry-After header, and no throttle message. IF this endpoint compares codes without also capping attempts per code, an attacker can brute-force the code space (a 6-digit OTP is only 1e6 possibilities). This is an OBSERVATION, not a proof: a per-code attempt cap is indistinguishable from no limit when every guess is answered "invalid", a limiter above ${BURST} attempts would be missed, and a real endpoint may reject our attempts for lack of a pending-verification session. Confirm by hand that a code's wrong guesses are bounded.`,
      fix: "Rate-limit verification attempts per account/phone/IP (e.g. 3-5 tries then a timed lockout with exponential backoff), invalidate the code after a few failures and force reissue, and cap the code's lifetime. express-rate-limit or an equivalent gateway limiter on the verify route is the minimum.",
    };
  }
  return null;
}
