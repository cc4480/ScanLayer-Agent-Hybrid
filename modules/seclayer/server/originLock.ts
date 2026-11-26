import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";

// Origin lock: only serve requests that came through Cloudflare.
//
// Railway's edge accepts a connection for seclayer.app from anyone who dials
// it directly (e.g. `curl --resolve seclayer.app:443:<railway edge ip>`), which
// skips Cloudflare's WAF, DDoS protection and bot rules entirely. With
// ORIGIN_AUTH_SECRET set, every request must carry that secret in the
// X-Origin-Auth header, which a Cloudflare Transform Rule adds (and overwrites,
// so a client cannot supply its own). Off when the variable is unset, so the
// app deploys unchanged until the Cloudflare rule is in place.
export const ORIGIN_AUTH_HEADER = "x-origin-auth";

// Railway's health check dials the container directly, never through
// Cloudflare, so it can never carry the header.
const EXEMPT_PATHS = new Set(["/api/system/health"]);

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

export function originLock(secret: string | undefined) {
  const expected = secret?.trim();
  return (req: Request, res: Response, next: NextFunction) => {
    if (!expected || EXEMPT_PATHS.has(req.path)) return next();
    const got = req.get(ORIGIN_AUTH_HEADER);
    if (got && safeEqual(got, expected)) return next();
    res.status(403).type("text/plain").send("Forbidden");
  };
}
