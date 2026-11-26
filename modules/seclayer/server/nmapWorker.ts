// Background worker for one nmap scan's lifecycle — mirrors scanWorker.ts's
// conventions (status guards before every write, live event stream, refund
// handled at the DB layer) adapted for a single long-running process instead
// of many small probes. Unlike scanWorker.ts this needs no injected
// dependency (no OOB collaborator equivalent), so it's a plain exported async
// function rather than a closure factory — a deliberate simplification.
import { db } from "./db.js";
import * as scanEvents from "./scanEvents.js";
import { resolveNmapTarget } from "./nmap/resolve.js";
import { nmapUnlocked } from "./activeProbeGate.js";
import { runNmap, killNmapProcess } from "./nmap/run.js";
import { parseNmapXml } from "./nmap/parseXml.js";
import { compileNmapResult } from "./nmap/compile.js";
import { nmapVersionString } from "./nmap/detect.js";

async function isCanceled(scanId: string): Promise<boolean> {
  return (await db.getNmapScan(scanId))?.status === "canceled";
}

// Same cadence as scanWorker's lease refresh, well inside STALE_LEASE_MS.
const LEASE_REFRESH_MS = 30 * 1000;
// A cancel request can land on any replica, but only the replica running the
// scan holds the nmap process. The owner polls for a cancellation made
// elsewhere and kills its own process, instead of letting nmap run to its
// 30-minute timeout for a result that will be discarded.
const CANCEL_POLL_MS = 5 * 1000;

export async function processNmapScanJob(scanId: string): Promise<void> {
  // Hold the lease for the whole run so recovery on another replica (boot or
  // the periodic sweep) can tell this scan is alive.
  void db.touchNmapScan(scanId).catch(() => {});
  const lease = setInterval(() => { void db.touchNmapScan(scanId).catch(() => {}); }, LEASE_REFRESH_MS);
  lease.unref?.();
  const stopCancelWatch = watchForCancel(scanId, isCanceled, killNmapProcess);
  try {
    await runNmapScanJob(scanId);
  } finally {
    clearInterval(lease);
    stopCancelWatch();
  }
}

// Polls for a cancellation and kills the process once one is seen. Returns a
// stop function. Exported (with injectable checks) for tests.
export function watchForCancel(
  scanId: string,
  canceled: (id: string) => Promise<boolean>,
  kill: (id: string) => unknown,
  intervalMs = CANCEL_POLL_MS,
): () => void {
  let killed = false;
  const timer = setInterval(() => {
    if (killed) return;
    canceled(scanId)
      .then((c) => { if (c && !killed) { killed = true; kill(scanId); } })
      .catch(() => {});
  }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}

async function runNmapScanJob(scanId: string): Promise<void> {
  let stream: ReturnType<typeof scanEvents.openStream> | undefined;
  try {
    const scan = (await db.getNmapScan(scanId));
    if (!scan || await isCanceled(scanId)) return;

    stream = scanEvents.openStream(scanId);
    const emit = stream.emit;
    emit("system", `Resolving ${scan.url}…`);

    (await db.updateNmapScan(scanId, { status: "scanning", startedAt: new Date().toISOString() }));

    // Resolved fresh here (not reused from launch time) so a DNS answer that
    // changed between "user clicked launch" and "the worker actually runs"
    // is re-validated — see nmap/resolve.ts's doc comment.
    const { hostname, ip } = await resolveNmapTarget(scan.url);
    if (await isCanceled(scanId)) return;
    // The launch-time proof can be minutes old by now; the scan only runs while it still holds.
    if (!(await nmapUnlocked(scan.userId, scan.url)).ok) {
      throw new Error("The domain ownership proof (the verification file) is no longer live, so the scan was not run.");
    }
    (await db.updateNmapScan(scanId, { resolvedIp: ip }));
    emit(
      "system",
      scan.deep
        ? `Resolved ${hostname} → ${ip}. Launching deep nmap scan (all 65535 ports, -sV, -O, --script vuln)…`
        : `Resolved ${hostname} → ${ip}. Launching nmap scan (top 1000 ports + high-risk service ports, -sV, -O, --script vuln)…`,
    );

    const { xml, durationMs, args } = await runNmap(scanId, ip, emit, undefined, scan.deep);
    if (await isCanceled(scanId)) return; // discard a result that arrived after cancellation

    emit("system", "Scan complete — parsing results…");
    const parsed = parseNmapXml(xml);
    const result = compileNmapResult(parsed, {
      targetHost: hostname,
      resolvedIp: ip,
      nmapVersion: nmapVersionString() || "unknown",
      durationMs,
      scanArgs: args,
    });

    if (await isCanceled(scanId)) return;
    (await db.updateNmapScan(scanId, {
      status: "complete",
      nmapVersion: result.nmapVersion,
      result,
      rawXml: xml,
      completedAt: new Date().toISOString(),
    }));
    const openPorts = result.ports.filter((p) => p.state === "open").length;
    const detected = result.vulnFindings.filter((f) => f.outcome === "finding").length;
    emit(
      "result",
      `Found ${openPorts} open port(s), ${detected} DETECTED vuln-script hit(s) (${result.vulnFindings.length} scripts ran).`,
    );
  } catch (err: any) {
    if (await isCanceled(scanId)) return; // already canceled — don't overwrite with a failure
    const message = err?.message || "The network reconnaissance scan could not be completed.";
    if (stream) stream.emit("system", `Scan failed: ${message}`);
    (await db.updateNmapScan(scanId, { status: "failed", error: message, completedAt: new Date().toISOString() }));
  } finally {
    if (stream) stream.close();
  }
}
