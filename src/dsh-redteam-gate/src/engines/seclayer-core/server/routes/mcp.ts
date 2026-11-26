// MCP endpoint: any external agent can call this with an API key to run the full
// diagnostic-and-AI pipeline synchronously and get back the same report quality
// as the dashboard. Active exploit probing only runs once the key's owner has
// verified ownership of the target's domain; otherwise passive recon only.
import express from "express";
import { db } from "../db.js";
import { config } from "../config.js";
import { rateLimit } from "../rateLimit.js";
import { runDiagnostics, compileStaticFindings, compileScanEvidence, assertScanTargetSafe } from "../scanner.js";
import { scanSlots, withScanLease } from "../scanWorker.js";
import { generateAiReport } from "../deepseek.js";
import { activeProbesUnlocked } from "../activeProbeGate.js";
import { asyncHandler } from "../asyncHandler.js";
import type { RouteContext } from "./context.js";

export function registerMcpRoutes(app: express.Express, ctx: RouteContext) {
  // Unlike /api/scans (fire-and-forget, backed by the same limiter), this
  // endpoint runs the full diagnostic-and-AI pipeline synchronously in-process
  // per call — with no limit here, a caller could burst enough concurrent
  // heavy scans to exhaust the single Node process and starve every other
  // user's scans, a real availability risk the credit cost alone doesn't stop.
  const mcpLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    keyPrefix: "mcp-scan",
    message: "MCP scan rate limit reached. Please wait a moment before the next call.",
  });
  // How long the request waits for the finished report before answering 202 and letting the scan
  // finish in the background. Cloudflare closes a proxied request that has produced no response in
  // about 100 seconds and answers the client 524, while the scan carries on, spends its credit and
  // is saved: a full scan with active probes can run well past that. Staying under the cutoff turns
  // that failure into an answer the client can act on. Read per request so tests can shorten it.
  const syncWaitMs = () => Math.max(1, Number(process.env.MCP_SYNC_WAIT_MS) || 80_000);

  app.post("/api/mcp/scan", mcpLimiter, asyncHandler(async (req, res) => {
    const { url, apiKey, authHeader, aggressiveProbes } = req.body;
    if (!url || !apiKey) {
      return res.status(400).json({ error: "Missing parameters. required: url, apiKey" });
    }

    // Reject SSRF / malformed targets before validating the key or spending a credit.
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Target URL cannot be scanned." });
    }

    const invalidKey = () => res.status(401).json({
      error: config.freeMode
        ? "Invalid API Key — an active key is required."
        : "Invalid API Key, active key required, or insufficient credits. Get credits at seclayer.app.",
    });

    // Identify the key owner WITHOUT spending anything yet, so the in-flight cap below can refuse
    // before a credit is taken. The dashboard has this cap; this path used to have only a per-IP
    // limiter, so one key could keep every scan slot busy for everyone else by queueing five scans a
    // minute for as long as it liked.
    const keyOwner = await db.validateApiKey(apiKey);
    if (!keyOwner) return invalidKey();
    if ((await db.countInFlightScans(keyOwner.id)) >= config.maxInFlightScansPerUser) {
      res.setHeader("Retry-After", "30");
      return res.status(429).json({ error: `You already have ${config.maxInFlightScansPerUser} scans queued or running. Wait for one to finish before starting another.` });
    }

    // In free mode scans cost nothing; otherwise take 1 credit atomically (re-checks the balance at
    // the moment of deduction, so concurrent calls cannot share the last credit).
    const user = config.freeMode ? keyOwner : (await db.validateApiKeyAndDeduct(apiKey, 1));
    if (!user) return invalidKey();

    // Create the scan record now, before running the pipeline — not just
    // after success. This mirrors the dashboard flow so an MCP scan is (a)
    // visible in scan history immediately, (b) covered by db.recoverStuckScans
    // if the process crashes mid-pipeline, and (c) refundable below if the
    // pipeline throws, rather than the credit silently vanishing with no
    // record of what happened to it.
    const scan = (await db.createScan(user.id, url, authHeader));
    // Lease BEFORE going in-flight, so the stuck-scan sweeper never sees this
    // scan 'scanning' without a heartbeat (withScanLease keeps it fresh below).
    (await db.touchScan(scan.id));
    (await db.updateScan(scan.id, { status: "scanning" }));

    // The whole scan as one promise that never rejects, so it can outlive the request: it settles
    // with either the report or the refunded balance, and records the result in the database either
    // way. Nothing in it touches `res`.
    const work = (async (): Promise<{ ok: true; body: Record<string, unknown> } | { ok: false; creditsRemaining: number }> => {
      try {
        // Active exploit probing only runs once this key's owner has verified
        // ownership of the target's domain; otherwise passive recon only.
        const allowActiveProbes = await activeProbesUnlocked(user.id, url);
        // Aggressive tier (SSTI/LFI/XXE/CORS/CRLF/open-redirect/NoSQL/host-header +
        // stored XSS) is a more-invasive OPT-IN — the caller must ask for it, and it
        // still requires active probing to be unlocked, exactly like the dashboard's
        // "Full Attack" toggle (see server/routes/scans.ts).
        const allowAggressiveProbes = allowActiveProbes && aggressiveProbes === true;

        // It MUST take a slot from the same per-instance pool as every other scan. Without it this
        // endpoint was capped by nothing: N concurrent MCP requests started N concurrent scans,
        // ignoring maxConcurrentScans entirely, and an OOM here kills every other scan on the
        // instance. Under load the scan WAITS for a slot rather than piling on.
        const diagnostics = await withScanLease(scan.id, () => scanSlots.run(() =>
          runDiagnostics(url, authHeader, { allowActiveProbes, allowAggressiveProbes, oob: ctx.oobCollaborator, scanId: scan.id })));
        const staticCompiled = compileStaticFindings(diagnostics);
        // Use the key owner's personal DeepSeek key (BYOK) when set.
        const aiReport = await withScanLease(scan.id, async () =>
          generateAiReport(url, diagnostics, staticCompiled, (await db.getUserDeepseekKey(user.id))));

        const evidence = compileScanEvidence(diagnostics);
        (await db.updateScan(scan.id, {
          status: "complete",
          score: aiReport.score,
          severity: aiReport.severity,
          findings: aiReport.findings,
          aiSummary: aiReport.aiSummary,
          aiReasoning: aiReport.aiReasoning,
          executiveBreakdown: aiReport.executiveBreakdown,
          evidence,
          completedAt: new Date().toISOString(),
        }));

        return {
          ok: true,
          body: {
            success: true,
            targetUrl: url,
            postureScore: aiReport.score,
            vulnerabilityLevel: aiReport.severity,
            analysisSummary: aiReport.aiSummary,
            executiveBreakdown: aiReport.executiveBreakdown,
            securityFindings: aiReport.findings,
            evidence,
            creditsRemaining: user.credits,
          },
        };
      } catch (err: any) {
        // Refund the credit spent on a failed scan — except in free mode, where
        // none was spent, so the balance is reported unchanged.
        let creditsRemaining = user.credits;
        try {
          if (!config.freeMode) creditsRemaining = (await db.addCredits(user.id, 1, "purchase")).credits;
          (await db.updateScan(scan.id, {
            status: "failed",
            error: err?.message || "The scan could not be completed.",
          }));
        } catch (bookkeeping) {
          console.error(`[mcp] scan ${scan.id}: could not record the failure or refund the credit:`, bookkeeping);
        }
        // Full error to the server log only: an internal failure (database,
        // DNS, upstream AI) can carry details that don't belong in an API response.
        console.error(`[mcp] scan ${scan.id} failed:`, err);
        return { ok: false, creditsRemaining };
      }
    })();

    // Wait for the report, but not past the proxy's cutoff.
    let timer: NodeJS.Timeout | undefined;
    const outcome = await Promise.race([
      work,
      new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), syncWaitMs()); }),
    ]);
    if (timer) clearTimeout(timer);

    if (outcome === null) {
      // Still running. The scan goes on and is saved; the client fetches the report when it is done.
      return res.status(202).json({
        success: true,
        pending: true,
        creditsRemaining: user.credits,
        scanId: scan.id,
        status: "scanning",
        pollUrl: `/api/mcp/scans/${scan.id}`,
        message: "The scan is still running. Poll pollUrl with the X-API-Key header; it answers 409 until the scan finishes, then returns the full report.",
      });
    }
    if (outcome.ok) return res.json(outcome.body);
    return res.status(500).json({ error: "Internal audit scanning failed", scanId: scan.id, creditsRemaining: outcome.creditsRemaining });
  }));

  // --- Read access for agents (no credit cost) ---
  // Retrieval is READ-ONLY: it never runs the pipeline and never spends a
  // credit, so an agent can review results it already paid for (and check scan
  // status/history) without launching a new scan. Authenticated by the same API
  // key as the scan endpoint, accepted ONLY in the X-API-Key header: a key in a URL is
  // written to every proxy, CDN and platform request log along the way. Its own lighter limiter (distinct keyPrefix) so cheap reads
  // don't share the heavy scan budget.
  const mcpReadLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyPrefix: "mcp-read",
    message: "MCP read rate limit reached. Please wait a moment before the next call.",
  });

  const keyOwner = async (req: express.Request) => {
    const key = (req.header("x-api-key") || "").toString().trim();
    return key ? (await db.validateApiKey(key)) : null;
  };

  // The query-string form used to be accepted. Refused outright, with the reason, rather than
  // ignored: ignoring it would answer 401 "invalid key" to someone whose key is fine, and the
  // key has already been logged by the time it arrives, so they should rotate it.
  const refuseQueryKey: express.RequestHandler = (req, res, next) => {
    if (req.query.apiKey === undefined) return next();
    res.status(400).json({ error: "Send the API key in the X-API-Key header. Keys in the query string are no longer accepted because URLs are logged; rotate any key that was sent this way." });
  };

  // List this key owner's recent scans (compact: no findings bodies), newest
  // first — so an agent can find the id of a scan to fetch in full below.
  app.get("/api/mcp/scans", mcpReadLimiter, refuseQueryKey, asyncHandler(async (req, res) => {
    const user = await keyOwner(req);
    if (!user) {
      return res.status(401).json({ error: "Invalid or missing API key. Pass it in the X-API-Key header." });
    }
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const scans = (await db.listScans(user.id)).slice(0, limit).map((s) => ({
      id: s.id,
      url: s.url,
      status: s.status,
      score: s.score ?? null,
      severity: s.severity ?? null,
      createdAt: s.createdAt,
      completedAt: s.completedAt ?? null,
    }));
    res.json({ success: true, scans });
  }));

  // Fetch one completed scan's full report by id — the SAME shape POST
  // /api/mcp/scan returns, so an agent (and the MCP formatter) can consume a
  // retrieved report identically to a freshly-run one. Suppression is applied
  // and the score recalculated via the shared read-model.
  app.get("/api/mcp/scans/:id", mcpReadLimiter, refuseQueryKey, asyncHandler(async (req, res) => {
    const user = await keyOwner(req);
    if (!user) {
      return res.status(401).json({ error: "Invalid or missing API key. Pass it in the X-API-Key header." });
    }
    const raw = (await db.getScan(req.params.id));
    // 404 (not 403) when the scan isn't this owner's, so an id can't probe existence.
    if (!raw || raw.userId !== user.id) {
      return res.status(404).json({ error: "Scan not found." });
    }
    if (raw.status !== "complete") {
      return res.status(409).json({ error: `Scan is not complete (status: ${raw.status}). Only completed scans have a report.`, status: raw.status });
    }
    const scan = (await db.getScanWithSuppressedFindings(raw));
    res.json({
      success: true,
      targetUrl: scan.url,
      postureScore: scan.score,
      vulnerabilityLevel: scan.severity,
      analysisSummary: scan.aiSummary,
      executiveBreakdown: scan.executiveBreakdown,
      securityFindings: scan.findings,
      evidence: scan.evidence,
      createdAt: scan.createdAt,
      completedAt: scan.completedAt,
    });
  }));
}
