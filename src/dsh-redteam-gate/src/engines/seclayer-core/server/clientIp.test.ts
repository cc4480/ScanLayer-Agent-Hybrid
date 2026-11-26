import { test } from "node:test";
import assert from "node:assert/strict";
import { isCloudflareIp, resolveClientIp } from "./clientIp.js";

test("isCloudflareIp recognises Cloudflare edge addresses seen in production", () => {
  assert.equal(isCloudflareIp("104.22.148.8"), true);
  assert.equal(isCloudflareIp("162.159.116.134"), true);
  assert.equal(isCloudflareIp("::ffff:172.64.1.1"), true);
  assert.equal(isCloudflareIp("2606:4700::1"), true);
  assert.equal(isCloudflareIp("174.197.0.128"), false);
  assert.equal(isCloudflareIp("89.222.103.193"), false);
  assert.equal(isCloudflareIp("garbage"), false);
});

test("resolveClientIp uses CF-Connecting-IP only when the connecting hop is Cloudflare", () => {
  assert.equal(resolveClientIp("104.22.148.8", "174.197.0.128"), "174.197.0.128");
  // Direct-to-origin caller forging the header: ignored.
  assert.equal(resolveClientIp("174.197.0.128", "7.7.7.7"), "174.197.0.128");
  // Cloudflare hop without the header, or with junk: keep the hop.
  assert.equal(resolveClientIp("104.22.148.8", undefined), "104.22.148.8");
  assert.equal(resolveClientIp("104.22.148.8", "not-an-ip"), "104.22.148.8");
  assert.equal(resolveClientIp(undefined, "1.2.3.4"), undefined);
});
