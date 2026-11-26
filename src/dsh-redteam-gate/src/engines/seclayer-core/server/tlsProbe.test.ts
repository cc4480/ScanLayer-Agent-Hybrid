import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyTls, probeTls, type TlsObservation } from "./tlsProbe.js";

const NOW = Date.parse("2026-09-14T00:00:00Z");
const days = (n: number) => NOW + n * 86_400_000;

test("classifyTls: healthy cert on a current protocol yields no issues", () => {
  const obs: TlsObservation = { checked: true, reachable: true, protocol: "TLSv1.3", validToMs: days(90) };
  assert.deepEqual(classifyTls(obs, NOW), []);
});

test("classifyTls: expired certificate is a high-severity finding", () => {
  const obs: TlsObservation = { checked: true, reachable: true, protocol: "TLSv1.2", validToMs: days(-3), subject: "example.com" };
  const issues = classifyTls(obs, NOW);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].kind, "expired");
  assert.equal(issues[0].severity, "high");
  assert.match(issues[0].description, /3 day\(s\) ago/);
});

test("classifyTls: expiring inside a week is medium, inside the window is low", () => {
  assert.equal(classifyTls({ checked: true, reachable: true, protocol: "TLSv1.3", validToMs: days(5) }, NOW)[0].severity, "medium");
  assert.equal(classifyTls({ checked: true, reachable: true, protocol: "TLSv1.3", validToMs: days(18) }, NOW)[0].severity, "low");
});

test("classifyTls: a cert 21+ days out on a current protocol is fine", () => {
  assert.deepEqual(classifyTls({ checked: true, reachable: true, protocol: "TLSv1.3", validToMs: days(30) }, NOW), []);
});

test("classifyTls: a 90-day certificate is judged exactly as before", () => {
  const issued = (n: number) => ({ checked: true, reachable: true, protocol: "TLSv1.3", validFromMs: days(n - 90), validToMs: days(n) });
  assert.equal(classifyTls(issued(21.9), NOW)[0]?.severity, "low");
  assert.deepEqual(classifyTls(issued(22), NOW), []);
  assert.equal(classifyTls(issued(7.9), NOW)[0]?.severity, "medium");
});

test("classifyTls: a healthy short-lived certificate is not flagged for being short-lived", () => {
  // Let's Encrypt's 6-day certificates always sit inside a fixed 21-day
  // window, so every one was flagged on every scan.
  const sixDay = (remaining: number) =>
    ({ checked: true, reachable: true, protocol: "TLSv1.3", validFromMs: days(remaining - 6), validToMs: days(remaining) });
  assert.deepEqual(classifyTls(sixDay(5), NOW), []);
  assert.deepEqual(classifyTls(sixDay(2.5), NOW), []);
  // Inside its last third it should already have been renewed.
  const late = classifyTls(sixDay(1.5), NOW);
  assert.equal(late[0]?.kind, "expiring-soon");
  assert.equal(late[0]?.severity, "low");
  assert.match(late[0].description, /short-lived certificate \(valid for 6 days/);
  assert.equal(classifyTls(sixDay(0.5), NOW)[0]?.severity, "medium");
  assert.equal(classifyTls(sixDay(-0.1), NOW)[0]?.kind, "expired");
});

test("classifyTls: deprecated protocol is flagged; TLS 1.2/1.3 are not", () => {
  const dep = classifyTls({ checked: true, reachable: true, protocol: "TLSv1.1", validToMs: days(90) }, NOW);
  assert.equal(dep.length, 1);
  assert.equal(dep[0].kind, "deprecated-protocol");
  assert.equal(dep[0].severity, "medium");
  assert.deepEqual(classifyTls({ checked: true, reachable: true, protocol: "TLSv1.2", validToMs: days(90) }, NOW), []);
});

test("classifyTls: expired AND deprecated protocol yields both findings", () => {
  const issues = classifyTls({ checked: true, reachable: true, protocol: "TLSv1", validToMs: days(-1) }, NOW);
  assert.equal(issues.length, 2);
  assert.deepEqual(new Set(issues.map((i) => i.kind)), new Set(["expired", "deprecated-protocol"]));
});

test("classifyTls: an unchecked or unreachable observation yields nothing", () => {
  assert.deepEqual(classifyTls({ checked: false, reachable: false }, NOW), []);
  assert.deepEqual(classifyTls({ checked: true, reachable: false }, NOW), []);
});

test("probeTls: a plain-HTTP target is not checked (no handshake attempted)", async () => {
  const obs = await probeTls("http://example.com");
  assert.equal(obs.checked, false);
  assert.equal(obs.reachable, false);
});

test("probeTls: a malformed URL is not checked", async () => {
  const obs = await probeTls("not a url");
  assert.equal(obs.checked, false);
});
