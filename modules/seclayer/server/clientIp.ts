import net from "node:net";
import type { Request, Response, NextFunction } from "express";

// Cloudflare's published edge ranges (https://www.cloudflare.com/ips-v4 and
// /ips-v6, fetched 2026-09-25). They change rarely; a stale list only means a
// request from a new Cloudflare range keeps the Cloudflare node as its IP (the
// pre-existing behaviour), never that a spoofed header is trusted.
const CLOUDFLARE_RANGES = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
  "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
];

const cloudflare = new net.BlockList();
for (const cidr of CLOUDFLARE_RANGES) {
  const [addr, bits] = cidr.split("/");
  cloudflare.addSubnet(addr, Number(bits), net.isIPv6(addr) ? "ipv6" : "ipv4");
}

export function isCloudflareIp(ip: string): boolean {
  const clean = ip.replace(/^::ffff:/, "");
  const type = net.isIPv4(clean) ? "ipv4" : net.isIPv6(clean) ? "ipv6" : null;
  return type ? cloudflare.check(clean, type) : false;
}

// The visitor's IP. `proxyIp` is what Express resolved from the trusted proxy
// chain — on Railway that is the address that actually connected to Railway's
// edge, which clients cannot spoof. When that address is a Cloudflare node, the
// request genuinely came through Cloudflare, and Cloudflare's CF-Connecting-IP
// (which it refuses to accept from clients) is the real visitor. Anyone else
// sending CF-Connecting-IP is ignored.
export function resolveClientIp(proxyIp: string | undefined, cfConnectingIp: string | undefined): string | undefined {
  if (proxyIp && cfConnectingIp && isCloudflareIp(proxyIp)) {
    const candidate = cfConnectingIp.trim();
    if (net.isIP(candidate)) return candidate;
  }
  return proxyIp;
}

// Shadows Express's req.ip getter so every consumer (rate limits, access log,
// OOB source IP) sees the resolved visitor IP.
export function clientIpMiddleware(req: Request, _res: Response, next: NextFunction) {
  const resolved = resolveClientIp(req.ip, req.get("cf-connecting-ip"));
  if (resolved && resolved !== req.ip) {
    Object.defineProperty(req, "ip", { value: resolved, configurable: true, enumerable: true });
  }
  next();
}
