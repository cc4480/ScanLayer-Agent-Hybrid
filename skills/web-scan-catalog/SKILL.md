---
name: web-scan-catalog
description: Complete check catalogs for the two local scanners (SecLayer 156 checks, SecScan 197 checks) and the exact command to run each check by hand. Use when asked to scan a site without the scanner apps, to reproduce or explain a scanner finding, or to see what the scanners actually test. Prefer the MCP tools when they are available.
---

# Web scan catalog — run the checks yourself

Both local scanners are black-box HTTP/DNS testers whose value is the catalog: a fixed
list of checks, each with a pass/fail oracle. When the apps are unavailable, or the user
wants a scan without spinning one up, this file is that catalog plus the commands.

**Prefer the apps when they are up** — `mcp__seclayer__seclayer_scan` and
`mcp__secscan__scan_url` own scoring, the report and the fix prompts. This skill is the
fallback and the reference, not a replacement for the report.

## Ground rules

- Only scan a site the user owns or has authorised. A URL is not authorisation.
- Non-destructive: no writes, no deletes, no brute force. Rate-limit yourself (~1 req/s).
- Every finding needs evidence: the request and the response fragment that proves it.
- Never claim a check passed if you skipped it — say "not run" and why.
- Return findings inline (severity, evidence, fix). Write no report document unless asked.

## Common recipes

```bash
# headers + cookies
curl -sS -D - -o /dev/null --max-time 10 https://TARGET/
# body (first 200 KB) for secret/template matching
curl -sS --max-time 15 -A "scan/1.0" https://TARGET/ | head -c 200000
# TLS: negotiated protocol + certificate expiry
echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null | openssl x509 -noout -dates -subject
# DNS: A, NS, MX, TXT (SPF/DMARC), CAA, DS
Resolve-DnsName -Name TARGET -Type TXT -Server 1.1.1.1 -DnsOnly
# subdomains from certificate transparency
curl -sS "https://crt.sh/?q=%25.TARGET&output=json" | jq -r ".[].name_value" | sort -u
```

---

# Part 1 — SecLayer (156 checks)

Seven engines: IAST (passive), EASM (DNS/TLS/perimeter), SAST (secrets in served text),
SCA (library signatures), DAST (paths, templates, crawl), API_SEC, RED_TEAM (active probes).
Counts vary with the target because templates are tech-gated and fuzzing follows params.

| Engine | Checks | Gated |
|---|---|---|
| IAST — security headers | 5 | no |
| IAST — cookie flags | 2 | no |
| IAST — insecure deserialization | 1 | no |
| EASM — HTTP vs HTTPS | 1 | no |
| EASM — TLS certificate/protocol | 2 | no |
| EASM — DNS A + NS | 2 | no |
| EASM — subdomain enumeration | 33 | no |
| SAST — exposed-secret signatures | 6 | no |
| SCA — vulnerable-library signatures | 4 | no |
| DAST — sensitive paths | 12 | no |
| DAST — template pack | 61 defined (~40 run per tech) | tech |
| DAST — crawl / surface map | per site | tech |
| RED_TEAM — root-URL exploits | 5 | ownership |
| RED_TEAM — parameter injection fuzzing | per param (19 typical) | ownership |
| API_SEC — API probes | 4 | ownership |
| RED_TEAM — JWT weakness | 1 | ownership |
| RED_TEAM — DOM XSS (headless) | 1 | ownership + rendering |
| RED_TEAM — stored XSS (forms) | 1 | ownership |
| RED_TEAM — aggressive tier | 8 | ownership + opt-in |

## 1.1 Security headers (5)

`curl -sS -D - -o /dev/null https://TARGET/` — missing header is the finding, a weak
value (short `max-age`, `script-src *`) also is.

| Header | Pass | Fail |
|---|---|---|
| `content-security-policy` | present, `script-src` without `*`/`unsafe-eval` | absent or wildcard |
| `strict-transport-security` | `max-age` >= 31536000 | absent or short |
| `x-frame-options` | `DENY`/`SAMEORIGIN`, or CSP `frame-ancestors` | absent |
| `x-content-type-options` | `nosniff` | absent |
| `referrer-policy` | `strict-origin-when-cross-origin` or stricter | absent |

## 1.2 Cookie flags (2)

Judge each `Set-Cookie` **individually** so one secure cookie cannot mask an insecure
one. Findings: session cookie without `Secure`; without `HttpOnly`. Missing `SameSite` is
deliberately not reported. Skip deletion cookies (`Max-Age=0`, past `Expires`).

## 1.3 Insecure deserialization (1)

A server-issued cookie whose decoded value starts with a native serialization magic:
Java `rO0AB`, PHP `O:`/`a:`, Ruby `BAh7`, Python pickle `gASV`, .NET `AAEAAAD`.

## 1.4 Transport (1) + TLS posture (2)

```bash
curl -sS -o /dev/null -w "%{http_code} %{redirect_url}" http://TARGET/   # expect 301/308
echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null | openssl x509 -noout -dates
echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null | grep Protocol
```

Findings: no HTTPS; certificate expired or < 30 days; TLS < 1.2. A handshake that never
completes is "not tested", not "pass".

## 1.5 DNS resolution (2) + subdomains (33)

A must resolve, NS must answer (`Resolve-DnsName TARGET -Type A` / `-Type NS`). Enumerate
subdomains from crt.sh and the 33-entry perimeter list, resolve each, flag a CNAME/A to a
deprovisioned cloud service (takeover). A host serving a parking page is live, not vulnerable.

## 1.6 Secret signatures (6) — SAST

Fetch HTML plus every same-origin JS bundle and match. Report file and offset, never the value.

| Signature | Pattern | Severity |
|---|---|---|
| Stripe secret key | `sk_live_[0-9a-zA-Z]{24,}` | critical |
| GitHub OAuth token | `gho_[a-zA-Z0-9]{36}` | critical |
| PEM private key | `-----BEGIN … PRIVATE KEY-----` + 40+ base64 | critical |
| OpenAI API key | `sk-proj-…` / `sk-…T3BlbkFJ…` | critical |
| Supabase service_role | JWT payload `"role":"service_role"` | critical |
| AWS access key | `AKIA[0-9A-Z]{16}` | high |

## 1.7 Library signatures (4) — SCA

Identify library + version from served files, compare with the EOL floor: jQuery < 3.5,
Bootstrap < 4.3, AngularJS 1.x (all EOL), Lodash < 4.17.21 (prototype pollution).

## 1.8 Sensitive paths (12) + template pack (61)

GET each path; the oracle is the **body signature**, never the status alone (a SPA returns
200 + HTML for everything; reject HTML when the signature is a text file).

| Path | Signature |
|---|---|
| `/.env` | `^[A-Z][A-Z0-9_]*=` lines, not HTML |
| `/.git/config` | `[core]` or `repositoryformatversion` |
| `/.git/HEAD` | `ref: refs/` |
| `/phpinfo.php` | `<title>phpinfo()` |
| `/.aws/credentials` | `aws_access_key_id` |
| `/config.json` | JSON with secret-named keys |
| `/package-lock.json`, `/yarn.lock`, `/pnpm-lock.yaml`, `/composer.lock`, `/Gemfile.lock` | exact dependency versions disclosed (supply chain) |
| `/.npmrc` | `_authToken=` |

The 61-template pack adds tech-gated probes: Spring Actuator `/env` and `/health`,
Dockerfile, docker-compose.yml, package.json, .env backups, wp-config, phpMyAdmin,
Adminer, Apache mod_status, Laravel Telescope, Swagger UI, .git-credentials, web.config,
WEB-INF/web.xml, .htaccess, .htpasswd, SQL dumps, backup archives, .vscode/sftp.json,
.gitlab-ci.yml, composer.json/lock, Jolokia, /configprops, Symfony profiler, Rails info,
WP user enumeration, Solr admin, OpenAPI spec, GraphiQL, Elasticsearch, CouchDB,
Kubernetes API, RabbitMQ, Prometheus, Grafana, Kibana, GCP service account, SSH private
key, .npmrc, wp debug.log, xmlrpc, Drupal CHANGELOG, Joomla config, Laravel debugbar,
Jenkins, server logs, subdomain takeover, S3 listing, open directory, kubeconfig,
terraform.tfstate, .docker/config.json, .netrc, .aws/config, Tomcat manager, .DS_Store.
Read `server/templates.ts` for the current ids, `requests[].path` and matchers.

## 1.9 Crawl (DAST)

Fetch the root, extract same-origin `href`/`src`, follow up to ~25 pages, then repeat the
header/cookie/secret checks per page. A static site with no JS of its own is a correct
result, not a gap.

## 1.10 Red-team probes (5) — ownership required

Fire a real payload; confirm only with a receipt (literal response substring, or an OOB
callback). A status code alone is never proof.

| Probe | Payload | Oracle |
|---|---|---|
| SQL injection | `?id=1%27%20OR%201=1--` | DB error text (`SQL syntax`, `ORA-`, `pg_query`) |
| Reflected XSS | `?q=<script>alert(1)</script>` | unescaped reflection of the payload |
| OS command injection | `?ping=127.0.0.1;id` | `uid=`/`gid=`, or timing |
| SSRF | `?url=http://127.0.0.1:22` | internal banner / metadata body |
| Blind SSRF | `?url=http://COLLAB/token` | callback at the collaborator |

## 1.11 Parameter injection fuzzing — ownership required

Mine parameters from the crawl and JS bundles, fuzz each with the classes above, stop at
the first confirmed class per parameter.

## 1.12 API probes (4) — ownership required

| Probe | Run | Finding when |
|---|---|---|
| GraphQL introspection | `POST /graphql {"query":"{__schema{types{name}}}"}` | schema returned |
| Query-cost controls | deep nested query | no depth/cost limit |
| Exposed user object | `/api/v1/users/admin`, `/admin/users`, `/api/admin/users` | real user JSON |
| BOLA/IDOR | two identities, swap an id | another tenant's object |

## 1.13 JWT weakness (1)

Only when a Bearer JWT is present: `alg:none` accepted, HS256 verified with a guessable
key, or `kid` traversal.

## 1.14 DOM XSS (1) + stored XSS (1)

DOM XSS needs a headless browser: put a marker in the fragment/query and see whether it
reaches `innerHTML`/`eval`. Stored XSS: submit a form with a marker and re-fetch the page
that renders it. Without a browser, mark them "not run".

## 1.15 Aggressive tier (8) — ownership + opt-in

| Probe | Payload | Oracle |
|---|---|---|
| SSTI | `?name={{7*7}}` | computed product in the body |
| Path traversal | `?file=../../../../etc/passwd` | `root:x:0:0` |
| Open redirect | `?next=//evil.example/` | `Location` to the external host |
| CRLF injection | `?lang=en%0d%0aSet-Cookie:x` | injected header |
| CORS | `Origin: https://evil.example` | `ACAO` echoes it + `ACAC: true` |
| XXE (OOB) | `<!ENTITY x SYSTEM "http://COLLAB">` | callback |
| NoSQL | `{"username":{"$ne":null}}` | auth bypass |
| Host header | `Host: evil.example` | reflected into links/redirects |

---

# Part 2 — SecScan (197 checks)

SecScan's catalog is data-driven (`artifacts/api-server/src/lib/checkCatalog*.ts`). "HTTP"
reads responses and DNS, "Surface" crawls the site, "Repo" reads a GitHub repository.
Each entry below is `severity — check`. Run the HTTP/Surface ones with the recipes in
Part 1; repo checks need the repository, not the URL.

## HTTP — responses, cookies, files, DNS

### response headers and cookies  _(HTTP Security)_

- `critical` — No HTTPS / Plaintext HTTP
- `medium` — Missing HTTP Strict-Transport-Security (HSTS)
- `low` — HSTS max-age Too Short
- `high` — Missing Content-Security-Policy (CSP)
- `high` — CSP script-src Contains Wildcard
- `medium` — Content-Security-Policy is report-only (not enforced)
- `medium` — Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)
- `info` — Content-Security-Policy Allows Inline Styles
- `low` — CSP Missing object-src 'none' Directive
- `low` — CSP Missing base-uri Directive
- `medium` — Missing Clickjacking Protection (X-Frame-Options)
- `low` — Missing X-Content-Type-Options: nosniff
- `info` — Missing Referrer-Policy Header
- `info` — Missing Permissions-Policy Header
- `info` — Missing Cross-Origin-Opener-Policy (COOP)
- `info` — Missing Cross-Origin-Embedder-Policy (COEP)
- `info` — Missing Cross-Origin-Resource-Policy (CORP)
- `info` — Missing Cache-Control Headers
- `info` — Permissive CORS Policy (Wildcard Origin)
- `medium` — Mixed Content (HTTP Resources on HTTPS Page)
- `info` — Server Version Disclosure
- `info` — X-Powered-By Header Discloses Technology Stack
- `high` — Session Cookie Missing Secure Flag
- `medium` — Session Cookie Missing HttpOnly Flag
- `low` — Session Cookie Missing SameSite Attribute
- `low` — Non-Session Cookie Missing Secure Flag
- `info` — Non-Session Cookie Readable by JavaScript
- `info` — Non-Session Cookie Missing SameSite Attribute

### sensitive file exposure  _(Information Disclosure)_


### robots.txt disclosure  _(Information Disclosure)_

- `low` — robots.txt Discloses Sensitive Application Paths

### subresource integrity  _(Supply Chain Security)_

- `medium` — External Resources Missing Subresource Integrity (SRI)
- `high` — Page Loads a Script From a Host Tied to a Known Supply-Chain Attack

### verbose error pages  _(Information Disclosure)_

- `medium` — Verbose Error Pages Expose Internal Application Details
- `critical` — Flask/Werkzeug Interactive Debugger Exposed

### HTTP to HTTPS redirect  _(Transport Security)_

- `high` — HTTP Traffic Not Redirected to HTTPS

### rate-limit headers  _(Brute Force Protection)_

- `low` — Rate Limiting Not Advertised in Response Headers

### clickjacking headers  _(UI Security)_

- `medium` — X-Frame-Options Header Misconfigured

### directory listing  _(Information Disclosure)_

- `medium` — Directory Listing Enabled

### security.txt  _(Information Disclosure)_

- `info` — Missing security.txt (RFC 9116)

### HTTP methods  _(HTTP Security)_

- `medium` — HTTP TRACE Method Enabled (Cross-Site Tracing)
- `high` — Write HTTP Methods Advertised
- `medium` — HTTP CONNECT Method Enabled

### active CORS  _(CORS Misconfiguration)_

- `high` — CORS Misconfiguration — Credentials Allowed from Arbitrary Origin
- `low` — CORS — Origin Reflected Without Credentials

### open redirect  _(Unvalidated Redirects)_

- `medium` — Open Redirect Vulnerability

### Supabase RLS  _(Database Security)_

- `critical` — Supabase Tables Exposed — Row Level Security (RLS) Disabled
- `info` — Supabase Detected — Verify Row Level Security (RLS)

### DNS and email authentication  _(Email Security)_

- `high` — Missing SPF Record — Email Spoofing Possible
- `critical` — SPF Record Uses +all (Allows Any Sender)
- `medium` — SPF Record Uses ?all (Neutral — No Enforcement)
- `low` — SPF Record Exceeds DNS Lookup Limit
- `high` — Missing DMARC Record — No Email Authentication Enforcement
- `medium` — DMARC Policy Set to None (Monitoring Only — No Enforcement)
- `info` — DMARC Record Missing Aggregate Report Address (rua=)
- `low` — No DKIM Records Found Under Common Selectors
- `info` — DNSSEC Not Enabled

### mail transport security  _(Mail Transport Security)_

- `medium` — Mail Server Does Not Offer STARTTLS
- `high` — Mail Server TLS Certificate Expired
- `low` — Mail Server TLS Certificate Expiring Soon

### structured data and social metadata  _(Structured Data)_

- `low` — Internal Hostname Exposed in Structured Data
- `low` — Social Preview Asset Referenced Over HTTP
- `low` — Canonical URL Points to an External Domain
- `info` — Malformed JSON-LD Structured Data
- `info` — Structured Data Missing @context or @type
- `info` — No Structured Data Found
- `info` — Incomplete Open Graph Metadata
- `info` — Twitter Card Metadata Absent
- `info` — Page Excluded From Search Indexes

## Repository — source and dependency checks

### repository secrets  _(Credential Exposure)_


### Supabase migrations (RLS and policies)  _(Broken Access Control)_

- `low` — Supabase Function Runs With Its Owner's Rights and No Pinned search_path
- `medium` — Supabase View Bypasses Row Level Security (no security_invoker)
- `medium` — Supabase Storage Policy Lets Anyone List and Read
- `high` — Supabase Tables Created Without Row Level Security
- `low` — Supabase Policy Lets Anyone Insert
- `info` — Supabase Policy Opens
- `high` — Supabase Policy Lets Anyone Update, Delete or Read and Write
- `medium` — Supabase Policy Lets Every Signed-In User Reach All Rows
- `high` — Supabase Access Decided From user_metadata
- `medium` — Supabase SECURITY DEFINER Function Callable by Anyone
- `medium` — Supabase Table Holds a Sensitive-Looking Column
- `medium` — Supabase Storage Bucket Named Like Private Files Is Public
- `medium` — Supabase Anonymous Sign-Ins Are Enabled
- `low` — Supabase Email Sign-Ups Are Not Confirmed

### CI and configuration  _(Security Misconfiguration)_

- `high` — GitHub Actions Workflow Runs Pull-Request Code With Repository Secrets
- `high` — GitHub Actions Shell Step Interpolates Attacker-Controlled Text
- `medium` — GitHub Actions Workflow Requests write-all Permissions
- `medium` — GitHub Actions Step Prints a Secret
- `high` — Dockerfile Bakes a Credential Into the Image
- `high` — Webhook Edge Function Accepts Unsigned Requests
- `medium` — Supabase Edge Functions Configured Without JWT Verification
- `critical` — Firestore or Cloud Storage Rules Let Anyone Write
- `critical` — Realtime Database Rules Let Anyone Write
- `high` — Realtime Database Rules Let Anyone Read
- `medium` — Dockerfile Pipes a Download Into a Shell
- `low` — Container Runs as Root
- `low` — Dockerfile Base Image Is Not Pinned
- `high` — Compose Service Runs Privileged
- `low` — GitHub Actions Uses Third-Party Actions Pinned to a Mutable Tag
- `info` — GitHub Actions Passes Every Secret to a Called Workflow

### dangerous code patterns  _(Injection)_

- `high` — Secret Exposed Through a Client-Side Environment Prefix
- `high` — eval or new Function on Request Data
- `high` — SQL Built From Request Data by String Interpolation
- `medium` — CORS Allows Any Origin With Credentials
- `medium` — TLS Certificate Verification Disabled
- `medium` — AI Provider Key Used Directly in Browser Code
- `high` — Hardcoded JWT Signing Secret
- `high` — JWT Verification Accepts the none Algorithm
- `medium` — Raw SQL Built by String Concatenation or Interpolation
- `high` — Operating-System Command Built From Request Data
- `medium` — File Path Taken From Request Data
- `medium` — Server Fetches a URL Taken From Request Data
- `medium` — Redirect to an Address Taken From Request Data
- `medium` — Predictable Random Number Used for a Secret
- `medium` — Password Hashed With MD5 or SHA-1
- `low` — Session Cookie Without HttpOnly or Secure
- `medium` — dangerouslySetInnerHTML With Unsanitised Content
- `medium` — API Route Changes Data With No Sign-In Check Visible
- `medium` — Environment File Committed to the Repository

### dependency vulnerabilities (OSV)  _(Vulnerable Components)_

- `critical` — Malicious package:

## Surface — crawl, JS bundles, DNS posture

### Next.js __NEXT_DATA__ secrets  _(Credential Exposure)_

- `critical` — Stripe Live Secret Key in __NEXT_DATA__
- `critical` — Supabase Service Role Key in __NEXT_DATA__
- `critical` — Private Key in __NEXT_DATA__
- `critical` — AWS Access Key ID in __NEXT_DATA__
- `critical` — AWS Secret Access Key in __NEXT_DATA__
- `critical` — GitHub Token in __NEXT_DATA__
- `high` — SendGrid API Key in __NEXT_DATA__
- `high` — Slack Token in __NEXT_DATA__
- `critical` — Hardcoded Database Connection String in __NEXT_DATA__

### known-CVE and end-of-life versions  _(Outdated Software)_

- `critical` — PHP end-of-life release
- `high` — Nginx end-of-life release cycle
- `critical` — Apache HTTPD end-of-life release branch
- `critical` — Microsoft IIS 6.0 — CVE-2017-7269 WebDAV RCE

### dependency CVEs from an exposed manifest  _(Vulnerable Components)_


### JWT analysis  _(Session Management)_

- `critical` — JWT Using alg:none — Signature Verification Bypass
- `critical` — JWT Has Empty Signature — Possible Verification Bypass
- `high` — JWT Token Has No Expiry (exp Claim Missing)
- `high` — JWT Uses HS256 Without Expiry — Offline Brute-Force Risk
- `medium` — JWT Token Lifetime Excessive
- `medium` — Sensitive Data Stored in JWT Payload

### Supabase RLS and Firebase rules  _(Database Security)_

- `critical` — Supabase Service Role Key Exposed in Client-Side Code
- `info` — Supabase Backend Detected
- `critical` — Supabase Tables Readable Without Authentication (CVE-2025-48757)
- `info` — Supabase Tables Returned Empty Results To Anonymous Requests
- `critical` — Supabase Tables Accept Unauthenticated Writes
- `info` — Supabase Backend Detected — RLS Appears Configured
- `medium` — Supabase Storage Bucket List Exposed Without Authentication
- `critical` — Firestore Security Rules Allow Unauthenticated Read Access
- `info` — Firebase Backend Detected — Firestore Rules Appear Restrictive
- `critical` — Firebase Realtime Database Open to Unauthenticated Access
- `low` — Supabase Email Confirmation Disabled
- `medium` — Supabase Storage Files Listable Without Authentication
- `high` — Firebase Storage Files Listable Without Authentication

### cross-account access control  _(Broken Access Control)_

- `critical` — Broken Object-Level Authorisation (IDOR)
- `critical` — Records Enumerable by Editing the Identifier
- `high` — Records Readable Without Signing In

### API endpoint testing  _(API Security)_

- `high` — API Endpoints Served Without Authentication
- `critical` — API Records Readable by Another Account
- `critical` — Write Endpoints Reachable Without Authentication
- `high` — Sensitive Fields Returned by the API
- `medium` — Privilege Fields Accepted in Request Bodies
- `info` — No Rate Limiting Observed on Sensitive API Endpoints
- `critical` — SQL Injection in API Parameters

### public cloud storage buckets  _(Cloud Storage Misconfiguration)_

- `high` — Public S3 Bucket Listing
- `high` — Public Google Cloud Storage Bucket Listing
- `high` — Public Azure Blob Container Listing

### BaaS open data  _(BaaS Misconfiguration)_

- `critical` — PocketBase Collections Readable Without Authentication
- `critical` — Appwrite Collections Readable Without Authentication

### GraphQL introspection  _(API Security)_

- `medium` — GraphQL Introspection Enabled in Production
- `low` — GraphQL Field Suggestions Enabled
- `low` — GraphQL Query Batching Enabled
- `medium` — GraphQL IDE Exposed

### injection  _(Injection)_

- `high` — Reflected Cross-Site Scripting (XSS)
- `critical` — Server-Side Template Injection
- `medium` — HTTP Header Injection (CRLF)
- `critical` — SQL Injection (Error-Based)

### path traversal  _(Injection)_

- `critical` — Path Traversal / Local File Inclusion (LFI)

### SSRF  _(Server-Side Request Forgery)_

- `critical` — Server-Side Request Forgery (SSRF)

### source map exposure  _(Source Code Exposure)_

- `high` — JavaScript Source Map Exposed — Full Source Code Accessible

### exposed API documentation  _(API Security)_

- `medium` — Exposed API Documentation (OpenAPI / Swagger)

### health endpoint disclosure  _(Information Disclosure)_

- `info` — Health Endpoint Discloses Runtime Details

### subdomain takeover  _(DNS Security)_

- `critical` — Dangling CNAME to a Claimable Service

### JavaScript secret scanning  _(Credential Exposure)_

- `low` — AI provider called directly from the browser
- `low` — AI system prompt shipped in client-side code

### site crawl  _(Information Disclosure)_

- `high` — Insecure Deserialization — serialized object in a cookie

### port scan  _(Network Exposure)_


### TLS configuration check  _(Transport Security)_

- `medium` — Deprecated TLS Protocol Versions Accepted
- `high` — TLS Certificate Expired
- `high` — TLS Certificate Not Yet Valid
- `low` — TLS Certificate Expires Soon
- `high` — TLS Certificate Does Not Match the Hostname
- `high` — Self-Signed TLS Certificate
- `medium` — TLS Certificate Chain Incomplete
- `high` — TLS Certificate Not Trusted
- `medium` — TLS Certificate Key Too Short
- `medium` — TLS Certificate Signed With a Weak Hash
- `medium` — Weak Cipher Suite Negotiated
- `low` — Cipher Suite Without Forward Secrecy

### SSL Labs TLS grade  _(Transport Security)_

- `info` — TLS Grade Below A (SSL Labs)

### GitHub source code secrets  _(Credential Exposure)_


### LLM prompt injection  _(AI Feature Security)_

- `medium` — LLM Prompt Injection Extracts the System Prompt

### race condition  _(Business Logic)_

- `high` — Race Condition Allows a One-Time Action to Succeed Multiple Times

### business logic: checkout price  _(Business Logic)_

- `high` — Checkout Trusts the Client's Price

---

# Reporting a manual scan

Return, in this order:

1. **Verdict** — one line: risk level and whether anything is exploitable.
2. **Findings** — each with id, severity, title, the exact request, the evidence fragment,
   the impact in one sentence, and the fix.
3. **What ran vs skipped** — counts per group, with the skip reason (no ownership, no
   browser, no repository, target down).
4. **Coverage gaps** — name them explicitly; a clean result says nothing about a skipped check.

Severity floor: critical = live secret or RCE-class proof; high = auth bypass, injection
with a receipt, exposed admin surface; medium = missing control with a plausible path;
low = hygiene; info = observation.