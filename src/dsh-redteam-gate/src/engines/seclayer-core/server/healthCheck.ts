import type { Request, Response } from "express";
import { INSTANCE_ID } from "./instance.js";
import { safeEqual } from "./originLock.js";

// Liveness + readiness probe. Actually pings the datastore rather than
// reporting a hardcoded "Online", so an orchestrator (or the Docker
// HEALTHCHECK) can detect a process that is up but has lost its database and
// pull it out of rotation. Returns 503 when the DB is unreachable.
//
// The public answer is only what the navbar renders: status and version. It is
// unauthenticated and exempt from the origin lock, so anyone on the internet
// reads it. Uptime told them exactly when each deploy happened (so when a fix
// went live), and memory gave a load attacker a live gauge of the damage — so
// the operator fields below are served only to a request carrying
// HEALTH_DETAIL_TOKEN. With the token unset they are never served.
export const HEALTH_DETAIL_HEADER = "x-health-detail";

export interface HealthOptions {
  healthy: () => Promise<boolean>;
  appVersion: string;
  detailToken: string | undefined;
}

export function healthDetailAllowed(got: string | undefined, token: string | undefined): boolean {
  const expected = token?.trim();
  return !!expected && !!got && safeEqual(got, expected);
}

export function healthHandler(opts: HealthOptions) {
  return async (req: Request, res: Response) => {
    const dbOk = await opts.healthy();
    // Never cached: a detailed answer stored by Cloudflare or a browser would
    // be replayed to the public, which is the leak this module closes.
    res.set("Cache-Control", "no-store");
    const summary = { status: dbOk ? "Online" : "Degraded", version: opts.appVersion };
    if (!healthDetailAllowed(req.get(HEALTH_DETAIL_HEADER), opts.detailToken)) {
      res.status(dbOk ? 200 : 503).json(summary);
      return;
    }
    res.status(dbOk ? 200 : 503).json({
      ...summary,
      checks: { database: dbOk ? "ok" : "error" },
      uptimeSeconds: Math.round(process.uptime()),
      // Opaque per-process id, regenerated on every boot: the only way to tell
      // from outside whether one replica is serving or five (see instance.ts).
      instance: INSTANCE_ID,
      // Resident set size, for capacity work: a scan holds a headless browser
      // and hundreds of sockets, so safe concurrency is a memory question.
      memory: { rssMb: Math.round(process.memoryUsage().rss / 1048576) },
      timestamp: new Date().toISOString(),
    });
  };
}
