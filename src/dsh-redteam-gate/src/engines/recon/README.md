# Passive recon (`src/engines/recon/`)

This module gathers public information about a domain without touching the domain's own hosts.

## What is passive here

| Function | Where the request goes | Why it is passive |
|---|---|---|
| `dnsRecords(domain, resolver)` | Public recursive DNS resolvers (default `node:dns/promises`) | Answers come from the resolver's cache or from the zone's public DNS. No connection is made to any service the target runs. |
| `certTransparency(domain, fetchFn)` | `https://crt.sh/?q=%.<domain>&output=json` | Certificate Transparency logs are public. The query goes to crt.sh, not the target. |
| `subdomainsFromPublicRecords(domain, sources)` | Both of the above | Merges CT names with in-zone names that DNS MX, NS and CNAME records point at. |

Each function validates its input with `normalizeDomain` first. Anything that is not a bare DNS name is refused before any lookup happens.

## What is not passive (and is not in this module)

- Port scans, HTTP probes, banner grabs, zone transfer (AXFR) attempts, brute-forced subdomain resolution against the target's authoritative servers, and any `GET` to a host found in the results. These send traffic to the target. They belong in an ACTIVE tool that goes through `decideScope` in `src/scope.mjs`.
- Recon helpers never call `decideScope` against unverified domains, and they never send packets to a host the target controls.

## Caveats

- Asking a public resolver for a record is standard DNS. The resolver may itself query the zone's authoritative servers on a cache miss. That is normal internet behavior, but it is the reason DNS lookups are "public record" rather than "zero contact".
- The domain name is sent to a third party (crt.sh and the resolver). Treat that disclosure as part of the engagement scope decision.
- crt.sh is a public service with no SLA. Failures come back as `error` strings in the result, so a merge still returns the DNS results.

## Design choices

- **node:dns for DNS.** Built into Node, no dependency. The resolver is injectable, so tests use fakes.
- **crt.sh JSON for CT.** Free, no API key, returns a plain JSON array. Alternatives (Censys, SecurityTrails, VirusTotal) need an account or token. Keys are not stored or printed here.
- **Injected `fetchFn` and resolver.** Tests run with no network. The defaults are the real ones.
- **Strict validation.** IP addresses, URLs, ports, paths, wildcards, whitespace, single labels and trailing dots are refused. The check is a whitelist on DNS label syntax, not a blacklist.
- **Failures are data, not exceptions.** A single record type or CT query that fails is reported in `errors` or `ct.error`, so the rest of the result still returns.

## Output shape

All results are plain JSON-serializable objects.

```
dnsRecords        -> { domain, records: { A, AAAA, MX, TXT, NS, CNAME }, errors: { <type>: string } }
certTransparency  -> { domain, source: 'crt.sh', names: string[], error?: string }
subdomainsFromPublicRecords -> { domain, subdomains: [{ name, sources: ('crt.sh'|'dns')[] }], dns, ct }
```

## Tests

`node --test "test/recon/*.test.mjs"` (Node 24 does not accept a bare directory argument to `--test`). The tests use fake resolvers and fake fetch functions only.
