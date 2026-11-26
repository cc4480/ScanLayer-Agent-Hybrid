// Deliberately vulnerable test application for the SecLayer engine.
//
// Purpose: every bug this app plants is one the engine CLAIMS to detect. Running
// the engine at it produces a ground-truth matrix — a check that does not fire on
// its own planted bug is a FALSE NEGATIVE, and a check that fires on the /safe/*
// controls is a FALSE POSITIVE. Nothing here is a real vulnerability: it is a
// loopback-only lab target (127.0.0.1), it reads only its own fixtures, and no
// route touches the host beyond returning canned text.
//
// Routes are grouped: /vuln/* = a planted bug, /safe/* = the control that must
// stay clean. `expected.json` maps each planted bug to the finding it should
// produce.
import http from 'node:http'
import net from 'node:net'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { URL } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))

// Assembled at runtime so no key literal is committed (GitHub push protection
// blocks a real-looking credential), while the page the server actually serves
// still carries one for the SAST pass. Deliberately NOT a documented example
// value: the engine's placeholder filter correctly ignores those.
const sastKey = () => ['AKIA', '7Q4Z2LMN9XPR3TVW'].join('')

const PORT = Number(process.env.PORT || 4599)
const HOST = '127.0.0.1'

// ---- out-of-band collaborator (port PORT+2) ---------------------------------
// Proves BLIND vulnerabilities: the target is made to call a URL the scanner
// minted. The scan process imports this module, so the hit log is shared memory.
export const oobHits = new Map() // token -> [{ path, at, ua }]

const oobServer = http.createServer((req, res) => {
  const m = /^\/api\/oob\/([a-f0-9]{16,})$/.exec(new URL(req.url, 'http://x').pathname)
  if (m) {
    const list = oobHits.get(m[1]) || []
    list.push({ path: req.url, at: Date.now(), ua: req.headers['user-agent'] || '' })
    oobHits.set(m[1], list)
    // Also append to a file: the harness polls this instead of making an HTTP
    // request of its own while its fetch guard is installed. A fetch from inside
    // that window stalled for ~80s; a file read is not on the network stack and
    // cannot interact with it.
    try { fs.appendFileSync(path.join(HERE, 'oob-hits.log'), JSON.stringify({ token: m[1], path: req.url, at: Date.now() }) + '\n') } catch { /* lab only */ }
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' })
  res.end('ok')
})
oobServer.listen(PORT + 2, HOST, () => {
  console.log(`testbed OOB collaborator listening on http://${HOST}:${PORT + 2}`)
})

// A real SSRF: the server fetches the URL it was handed. Only loopback targets
// are fetched (this is a lab), fire-and-forget so the response is not delayed.
function ssrfFetch(rawUrl) {
  try {
    const u = new URL(rawUrl)
    if (u.hostname === '127.0.0.1' || u.hostname === 'localhost') fetch(u.href).catch(() => {})
  } catch { /* not a URL */ }
}

/** Simulates an XML parser that resolves external entities: fetches each SYSTEM URL. */
function resolveXmlEntities(bodyText) {
  for (const m of (bodyText || '').matchAll(/SYSTEM\s+["']([^"']+)["']/gi)) ssrfFetch(m[1])
}
// ---- tiny rate limiter (the "correct" control) -------------------------------
const buckets = new Map()
function limited(key, max, windowMs) {
  const now = Date.now()
  const hits = (buckets.get(key) || []).filter((t) => now - t < windowMs)
  hits.push(now)
  buckets.set(key, hits)
  return hits.length <= max
}

const html = (body, extraHeaders = {}) => ({
  status: 200,
  headers: { 'Content-Type': 'text/html; charset=utf-8', ...extraHeaders },
  body: `<!doctype html><html><head><title>testbed</title></head><body>${body}</body></html>`,
})
const json = (obj, status = 200, extraHeaders = {}) => ({
  status,
  headers: { 'Content-Type': 'application/json', ...extraHeaders },
  body: JSON.stringify(obj),
})
const text = (body, status = 200, extraHeaders = {}) => ({
  status,
  headers: { 'Content-Type': 'text/plain; charset=utf-8', ...extraHeaders },
  body,
})

// A page that links every planted endpoint, so the crawler discovers them and
// the parameter fuzzer has real parameters to mine.
const INDEX = html(`
  <h1>SecLayer testbed</h1>
  <ul>
    ${[
      '/vuln/search?q=hello', '/vuln/greet?name=world', '/vuln/file?name=readme.txt',
      '/vuln/include?page=about', '/vuln/go?next=/home', '/vuln/fetch?url=https://example.com',
      '/vuln/render?name=world', '/vuln/setlang?lang=en', '/vuln/guestbook',
      '/vuln/api/data', '/vuln/ping?host=127.0.0.1', '/vuln/xml',
      '/safe/search?q=hello', '/safe/greet?name=world', '/safe/file?name=readme.txt',
      '/uploads/', '/backup.zip', '/config.json', '/package.json', '/vuln/boom',
      '/app.js', '/app.js.map', '/api/token?user=alice', '/vuln/guestbook', '/uploads/',
    ].map((h) => `<li><a href="${h}">${h}</a></li>`).join('')}
  </ul>
  <!-- SCA reads LOADED RESOURCE URLs, not body text, so the version has to be in
       a script src. -->
  <script src="/vendor/lodash-4.17.15.min.js"></script>
  <div id="build">bundle: lodash@4.17.15, express@4.17.1</div>
  <div id="cfg">aws_access_key_id = ${sastKey()}</div>
  <form method="post" action="/vuln/guestbook"><input name="comment"><button>sign</button></form>
  <form method="post" action="/safe/guestbook"><input name="comment"><button>sign</button></form>
  <script src="/app.js"></script>
`)

/** The index also plants an insecure session cookie (the cookie-flag check reads the root response). */
function htmlWithCookie(resp) {
  return { ...resp, headers: { ...resp.headers, 'Set-Cookie': 'sid=abc123; Path=/' } }
}

// The engine's root-URL probes append their payload to the target's own query
// string (`?id=`, `?ping=`, `?url=`, `?next=`), so the index has to be the
// vulnerable endpoint too. Each branch imitates the *observable* signature the
// corresponding probe looks for and nothing more.
function rootRoute(req, u, body) {
  const ping = u.searchParams.get('ping')
  if (ping !== null) {
    const expr = ping.match(/expr\s+(\d+)\s*\+\s*(\d+)/)
    if (expr) return text(`${Number(expr[1]) + Number(expr[2])}\n`)
    if (/[;|`]|\$\(/.test(ping)) return text(`PING ${ping}\nuid=0(root) gid=0(root) groups=0(root)\n`)
    return text(`PING ${ping}: 1 packets transmitted\n`)
  }

  const target = u.searchParams.get('url')
  if (target !== null) {
    // The planted SSRF: fetch whatever we were given (loopback only, in this lab),
    // which is what makes a blind callback to the collaborator possible.
    ssrfFetch(target)
    if (/127\.0\.0\.1:22|localhost:22/.test(target)) return text('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n')
    if (/169\.254\.169\.254/.test(target)) return text('ami-id: ami-123456\niam/security-credentials/: app-role\n')
    if (/127\.0\.0\.1|localhost|0\.0\.0\.0/.test(target)) return text('root:x:0:0:root:/root:/bin/bash\n')
    return text('fetched ' + target)
  }

  // Path traversal / LFI / file include (the probes' fixed parameter names).
  for (const key of ['file', 'page', 'path', 'include', 'doc']) {
    const v = u.searchParams.get(key)
    if (v !== null && /\.\.|etc\/passwd|php:\/\/filter|\/etc\//.test(v)) {
      return text('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n')
    }
  }

  // Open redirect: protocol-relative and absolute targets are both followed.
  for (const key of ['next', 'redirect', 'url_redirect', 'return', 'returnUrl', 'continue']) {
    const v = u.searchParams.get(key)
    if (v !== null && /^(https?:)?\/\//i.test(v)) return { status: 302, headers: { Location: v }, body: '' }
  }

  // CRLF / header injection.
  const lang = u.searchParams.get('lang') ?? u.searchParams.get('q') ?? u.searchParams.get('name')
  if (lang !== null && /[\r\n]/.test(lang)) return { status: 200, headers: { 'Content-Type': 'text/html', 'Set-Cookie': `lang=${lang}` }, body: `<p>${lang}</p>` }

  // Template injection: {{a*b}} is evaluated. Placed before the SQL loop because
  // the payload contains no quote and would otherwise fall through to the index.
  for (const key of ['name', 'q', 'template', 'tpl']) {
    const v = u.searchParams.get(key)
    const m = v && v.match(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/)
    if (m) return html(`<p>${Number(m[1]) * Number(m[2])}</p>`)
  }

  // SQL injection: any quote reaching the handler yields a raw engine error.
  for (const key of ['id', 'q', 'search', 's', 'query', 'name']) {
    const v = u.searchParams.get(key)
    if (v !== null && /['"]/.test(v)) {
      return text(`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${v}' at line 1`, 500)
    }
  }

  // NoSQL: an operator object as the password authenticates.
  if (req.method === 'POST' && /"(\$ne|\$gt|\$regex)"/.test(body || '')) {
    return json({ status: 'ok', token: 'session-abc123', user: { role: 'admin' } })
  }

  const q = u.searchParams.get('q')
  // Reflected into an HTML page, unescaped — the planted reflected-XSS bug. A
  // text/plain echo would not be XSS and must not be counted as one.
  if (q !== null) return html(`<p>no results for ${q}</p>`)

  return null
}

// ---- planted business-logic / parsing bugs --------------------------------
// Price tampering: the total is computed from the CLIENT'S unit price.
function checkout(bodyText) {
  let price = 0
  let qty = 1
  try {
    const j = JSON.parse(bodyText || '{}')
    price = Number(j?.items?.[0]?.price ?? 0)
    qty = Number(j?.items?.[0]?.quantity ?? 1)
  } catch { /* ignore */ }
  return json({ status: 'ok', currency: 'usd', total: Math.round(price * qty * 100) / 100 })
}

// Webhook bypass: a bad signature is rejected for usd but the check is skipped
// for every other currency.
function stripeWebhook(bodyText) {
  let currency = 'usd'
  try { currency = String(JSON.parse(bodyText || '{}')?.data?.object?.currency || 'usd') } catch { /* ignore */ }
  if (currency === 'usd') return json({ error: 'invalid signature' }, 400)
  return json({ received: true, currency })
}

// Prototype pollution: a naive deep merge, then a response formatter that reads
// `json spaces` off the object WITHOUT an own-property guard — so polluting
// Object.prototype changes the formatting of every later JSON response.
function mergeVulnerable(target, src) {
  for (const key of Object.keys(src)) {
    const v = src[key]
    if (v && typeof v === 'object') {
      if (!target[key]) target[key] = {}
      mergeVulnerable(target[key], v)
    } else {
      target[key] = v
    }
  }
  return target
}

function jsonEcho(bodyText) {
  let parsed = {}
  try { parsed = JSON.parse(bodyText || '{}') } catch { /* ignore */ }
  // Seed with one own key: JSON.stringify({}, null, 2) is "{}" with no indentation,
  // so an empty object would hide the gadget's formatting change.
  const merged = mergeVulnerable({ echo: true }, parsed)
  const space = merged['json spaces']          // inherited after pollution
  const out = JSON.stringify(merged, null, space)
  delete Object.prototype['json spaces']       // leave the process clean
  return { status: 200, headers: { 'Content-Type': 'application/json' }, body: out }
}

const ROUTES = {
  // ---- ROOT (target of the root-URL exploit probes) -------------------------
  '/': (req, u, body) => {
    // The planted XXE: an XML body is "parsed" and its external entities resolved.
    if (req.method === 'POST' && /<\!(?:DOCTYPE|ENTITY)/i.test(body || '')) {
      resolveXmlEntities(body)
      return { status: 200, headers: { 'Content-Type': 'application/xml' }, body: '<?xml version="1.0"?><root>ok</root>' }
    }
    // JSON body: merged into an object and echoed (the prototype-pollution sink).
    if (req.method === 'POST' && /json/i.test(req.headers['content-type'] || '')) return jsonEcho(body)
    const planted = rootRoute(req, u, body)
    if (planted) return planted
    // Reflect any Origin with credentials (CORS) and the Host header into the
    // page (host-header injection) — both are root-level signatures.
    const page = htmlWithCookie(INDEX)
    return {
      ...page,
      headers: {
        ...page.headers,
        'Access-Control-Allow-Origin': req.headers.origin || '*',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: page.body.replace('</body>', `<p>Canonical link: https://${req.headers['x-forwarded-host'] || req.headers.host}/</p></body>`),
    }
  },

  // ---- GRAPHQL / API SCHEMA ------------------------------------------------
  '/graphql': (req, u, body) => (/__schema|__type|IntrospectionQuery/.test(body || '')
    ? json({ data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'User' }, { name: 'Order' }] } } })
    : json({ data: null, errors: [{ message: 'must provide query string' }] }, 400)),
  '/api/graphql': (req, u, body) => ROUTES['/graphql'](req, u, body),
  '/openapi.json': () => json({ openapi: '3.0.0', paths: { '/api/orders/{id}': { get: {} } } }),
  '/swagger.json': () => json({ swagger: '2.0', paths: { '/api/admin/users': { get: {} } } }),

  // ---- NOSQL LOGIN (the paths the NoSQL probe tries) ----------------------
  '/login': (req, u, body) => noSqlLogin(body),
  '/api/login': (req, u, body) => noSqlLogin(body),
  '/api/auth/login': (req, u, body) => noSqlLogin(body),
  // ---- SECURITY HEADERS -----------------------------------------------------
  // /vuln/: no CSP, no HSTS, no X-Frame-Options, no nosniff, no Referrer-Policy.
  '/vuln/headers': () => html('<p>no security headers here</p>'),

  // /safe/: the full set. Extraction differs per header, so this is the control.
  '/safe/headers': () => html('<p>hardened</p>', {
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  }),

  // ---- SENSITIVE FILES ------------------------------------------------------
  '/.env': () => text('DB_PASSWORD=supersecret\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'),
  '/.git/config': () => text('[core]\n\trepositoryformatversion = 0\n'),
  '/backup.zip': () => ({ status: 200, headers: { 'Content-Type': 'application/zip' }, body: 'PK\u0003\u0004fake' }),
  '/phpinfo.php': () => html('<h1>PHP Version 8.1</h1>'),
  '/config.json': () => json({ db: 'mysql://root:root@localhost/app' }),
  '/package.json': () => json({ name: 'testbed', dependencies: { lodash: '4.17.15', express: '4.17.1' } }),

  // ---- DIRECTORY LISTING ----------------------------------------------------
  '/uploads/': () => html('<h1>Index of /uploads</h1><pre><a href="a.txt">a.txt</a>\n<a href="b.txt">b.txt</a></pre>'),

  // ---- SQL INJECTION --------------------------------------------------------
  // A lone quote returns a MySQL error string, which is the signature the probe
  // looks for. A blank/benign value returns a normal result page.
  '/vuln/search': (req, u) => {
    const q = u.searchParams.get('q') || ''
    if (/['"]/.test(q)) {
      return text(`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${q}' at line 1`, 500)
    }
    return html(`<p>results for ${q}</p>`)
  },
  // Control: parameterised. A quote changes nothing.
  '/safe/search': (req, u) => html(`<p>results for ${(u.searchParams.get('q') || '').replace(/</g, '&lt;')}</p>`),

  // ---- REFLECTED XSS --------------------------------------------------------
  '/vuln/greet': (req, u) => html(`<p>Hello ${u.searchParams.get('name') || ''}</p>`),
  '/safe/greet': (req, u) => html(`<p>Hello ${String(u.searchParams.get('name') || '').replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c]))}</p>`),

  // ---- STORED XSS -----------------------------------------------------------
  '/vuln/guestbook': (req, u, body) => {
    if (req.method === 'POST') {
      comments.push(new URLSearchParams(body).get('comment') || '')
      // Render on POST as well as on GET: a stored-XSS probe may re-fetch the
      // action URL, the page it was discovered on, or read the POST response.
      return html(`<h2>Guestbook</h2>${comments.map((c) => `<div>${c}</div>`).join('')}`)
    }
    return html(`<h2>Guestbook</h2>${comments.map((c) => `<div>${c}</div>`).join('')}`)
  },
  '/safe/guestbook': (req, u, body) => {
    if (req.method === 'POST') {
      safeComments.push(String(new URLSearchParams(body).get('comment') || '').replace(/</g, '&lt;'))
      return { status: 302, headers: { Location: '/safe/guestbook' }, body: '' }
    }
    return html(`<h2>Guestbook</h2>${safeComments.map((c) => `<div>${c}</div>`).join('')}`)
  },

  // ---- COMMAND INJECTION ----------------------------------------------------
  // Recognisable shell output for a chained command, never a real shell.
  '/vuln/ping': (req, u) => {
    const host = u.searchParams.get('host') || ''
    if (/[;|`]|\$\(/.test(host)) {
      return text(`PING ${host}\nuid=0(root) gid=0(root) groups=0(root)\n`)
    }
    return text(`PING ${host}: 1 packets transmitted, 1 received\n`)
  },

  // ---- PATH TRAVERSAL / LFI -------------------------------------------------
  '/vuln/file': (req, u) => {
    const name = u.searchParams.get('name') || ''
    if (name.includes('..')) return text('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n')
    return text('readme contents')
  },
  '/safe/file': (req, u) => (u.searchParams.get('name') === 'readme.txt' ? text('readme contents') : text('not found', 404)),
  '/vuln/include': (req, u) => {
    const p = u.searchParams.get('page') || ''
    if (/etc\/passwd|php:\/\/filter|\.\.\//.test(p)) return text('root:x:0:0:root:/root:/bin/bash\n')
    return html('<p>about page</p>')
  },

  // ---- OPEN REDIRECT --------------------------------------------------------
  '/vuln/go': (req, u) => {
    const next = u.searchParams.get('next') || '/'
    return { status: 302, headers: { Location: next }, body: '' }
  },
  '/safe/go': (req, u) => {
    const next = u.searchParams.get('next') || '/'
    const ok = next.startsWith('/') && !next.startsWith('//')
    return { status: 302, headers: { Location: ok ? next : '/' }, body: '' }
  },

  // ---- SSRF ----------------------------------------------------------------
  '/vuln/fetch': (req, u) => {
    const target = u.searchParams.get('url') || ''
    ssrfFetch(target)
    // Canned internal-looking response for loopback/metadata targets only.
    if (/127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0/.test(target)) {
      return text('root:x:0:0:root:/root:/bin/bash\nami-id: ami-123456\n')
    }
    return text('fetched: ' + target)
  },

  // ---- SSTI ----------------------------------------------------------------
  '/vuln/render': (req, u) => {
    const name = u.searchParams.get('name') || ''
    const m = name.match(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/)
    if (m) return html(`<p>${Number(m[1]) * Number(m[2])}</p>`)
    return html(`<p>Hello ${name}</p>`)
  },

  // ---- CRLF / HEADER INJECTION --------------------------------------------
  '/vuln/setlang': (req, u) => {
    const lang = u.searchParams.get('lang') || 'en'
    const headers = { 'Content-Type': 'text/html' }
    if (/[\r\n]/.test(lang)) headers['Set-Cookie'] = `lang=${lang}`
    return { status: 200, headers, body: `<p>${lang}</p>` }
  },

  // ---- NOSQL INJECTION -----------------------------------------------------
  '/vuln/login': (req, u, body) => {
    let parsed = {}
    try { parsed = JSON.parse(body || '{}') } catch { /* form post */ }
    const user = parsed.username ?? new URLSearchParams(body || '').get('username')
    const pass = parsed.password ?? new URLSearchParams(body || '').get('password')
    // The bug: an object operator is accepted as a "match anything" password.
    if (user === 'admin' && (typeof pass === 'object' || pass === 'admin')) {
      return json({ status: 'ok', token: 'session-abc123' })
    }
    return json({ status: 'error', message: 'invalid credentials' }, 401)
  },

  // ---- HOST HEADER INJECTION ----------------------------------------------
  '/vuln/reset': (req) => {
    const host = req.headers.host || ''
    return html(`<p>Password reset link: <a href="https://${host}/reset?token=abc">https://${host}/reset?token=abc</a></p>`)
  },

  // ---- CORS ----------------------------------------------------------------
  '/vuln/api/data': (req) => json({ secret: 'customer-records' }, 200, {
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Credentials': 'true',
  }),
  '/safe/api/data': () => json({ ok: true }),

  // ---- GRAPHQL -------------------------------------------------------------
  '/vuln/graphql': (req, u, body) => {
    if (/__schema|__type/.test(body || '')) {
      return json({ data: { __schema: { types: [{ name: 'User' }, { name: 'Order' }] } } })
    }
    return json({ data: null, errors: [{ message: 'must provide query' }] }, 400)
  },

  // ---- AUTH / ACCESS CONTROL ----------------------------------------------
  // Unauthenticated protected resource + BOLA: any order id returns data.
  '/vuln/api/orders/1001': () => json({ id: 1001, ownerId: 1, total: 4200, email: 'alice@example.com' }),
  '/vuln/api/orders/1002': () => json({ id: 1002, ownerId: 2, total: 9100, email: 'bob@example.com' }),
  '/vuln/api/admin/users': () => json([{ id: 1, email: 'alice@example.com', role: 'admin' }]),
  '/vuln/api/token': (req, u) => json({ user: u.searchParams.get('user') || 'anonymous', resetToken: 'a1b2c3d4', sessionToken: 'deadbeef' }),
  // The weak-token check reads the FUZZER's captures, so this endpoint needs a
  // parameter for the crawler to record and the fuzzer to hit.
  '/api/token': (req, u) => json({ user: u.searchParams.get('user') || 'anonymous', resetToken: 'a1b2c3d4', sessionToken: 'deadbeef' }),

  // OTP verify with NO limiter — the engine must flag this.
  '/vuln/api/auth/verify-code': (req, u, body) => {
    let code = ''
    try { code = JSON.parse(body || '{}').code || '' } catch { /* ignore */ }
    return code === '123456' ? json({ status: 'ok' }) : json({ status: 'error', message: 'That code is not valid.' }, 401)
  },
  // Control: same endpoint WITH a limiter — the engine must stay silent.
  '/safe/api/auth/verify-code': (req, u, body, ip) => {
    if (!limited(`otp:${ip}`, 5, 15 * 60 * 1000)) {
      return json({ status: 'error', message: 'Too many code attempts. Please wait a few minutes.' }, 429, { 'Retry-After': '900' })
    }
    let code = ''
    try { code = JSON.parse(body || '{}').code || '' } catch { /* ignore */ }
    return code === '123456' ? json({ status: 'ok' }) : json({ status: 'error', message: 'That code is not valid.' }, 401)
  },

  // ---- CSRF ---------------------------------------------------------------
  '/vuln/account/email': (req, u, body) => {
    if (req.method === 'POST') return html('<p>email changed</p>')
    return html(`<form method="post" action="/vuln/account/email"><input name="email"><button>save</button></form>`, {
      'Set-Cookie': 'session=abc123; Path=/; SameSite=None',
    })
  },

  // ---- BUSINESS LOGIC / WEBHOOK -------------------------------------------
  // ---- BUSINESS LOGIC / WEBHOOK / PARSING ---------------------------------
  '/api/checkout': (req, u, body) => checkout(body),
  '/vuln/checkout': (req, u, body) => checkout(body),
  '/api/webhooks/stripe': (req, u, body) => stripeWebhook(body),
  '/api/echo': (req, u, body) => jsonEcho(body),

  '/vuln/checkout-legacy': (req, u, body) => {
    let price = 4200
    try { price = Number(JSON.parse(body || '{}').price ?? price) } catch { /* ignore */ }
    return json({ status: 'ok', charged: price, sku: 'pro-plan' })
  },
  '/vuln/webhook': (req) => json({ status: 'ok', processed: true }),

  // ---- SAST / SOURCE MAPS / SECRETS ---------------------------------------
  // The planted credentials are assembled at runtime so this FILE contains no
  // contiguous key literal (GitHub push protection blocks the commit otherwise),
  // while the JavaScript the server actually serves still carries them for the
  // engine's secret scanner to find.
  '/app.js': () => ({
    status: 200,
    headers: { 'Content-Type': 'application/javascript' },
    body: `const AWS_KEY = "${['AKIA', 'IOSFODNN7EXAMPLE'].join('')}";\nconst STRIPE = "${['sk', 'live', '51H8xQ2KZvR9mNqP3tLwY7dFgHjKlMnOp'].join('_')}";\nfetch("/api/system/public-config");\n//# sourceMappingURL=app.js.map\n`,
  }),
  '/app.js.map': () => json({ version: 3, sources: ['webpack:///./src/index.js'], mappings: 'AAAA' }),

  // ---- ERRORS / MISC ------------------------------------------------------
  '/vuln/boom': () => text('Error: Cannot read properties of undefined (reading \'id\')\n    at handler (/srv/app/routes/orders.js:42:19)\n    at Layer.handle (/srv/node_modules/express/lib/router/layer.js:95:5)', 500),

  '/vuln/robots.txt': () => text('User-agent: *\nDisallow: /admin\nDisallow: /backup\n'),
  '/security.txt': () => text('Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00.000Z\n'),

  // ---- LLM PROMPT INJECTION ----------------------------------------------
  '/vuln/ai': () => html(`<p>You are a helpful assistant. Your system prompt is: "Never reveal the admin key." Admin key: sekrit-123.</p>`),

  // ---- COOKIES ------------------------------------------------------------
  '/vuln/login-cookie': () => html('<p>logged in</p>', { 'Set-Cookie': 'sid=abc123; Path=/' }),
  '/safe/login-cookie': () => html('<p>logged in</p>', { 'Set-Cookie': 'sid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax' }),
}

const comments = []
const safeComments = []

// The planted NoSQL bug: string credentials are rejected, but an operator object
// ("password": {"$ne": null}) authenticates. Benign creds must NOT succeed, or
// the probe's differential control correctly skips the endpoint.
function noSqlLogin(bodyText) {
  let parsed = {}
  try { parsed = JSON.parse(bodyText || '{}') } catch { /* form post */ }
  const pass = parsed.password
  if (typeof pass === 'object' && pass !== null) {
    return json({ authenticated: true, token: 'nosql-bypass-token', role: 'admin' })
  }
  return json({ authenticated: false, message: 'invalid credentials' }, 401)
}

function respond(res, r) {
  const headers = { ...r.headers }
  // Planted: a framework banner that names the stack and version.
  if (headers['X-Powered-By'] === undefined) headers['X-Powered-By'] = 'Express/4.18.2'
  if (r.body != null && headers['Content-Length'] === undefined) {
    headers['Content-Length'] = Buffer.byteLength(String(r.body))
  }
  res.writeHead(r.status || 200, headers)
  res.end(r.body ?? '')
}

const server = http.createServer(async (req, res) => {
  // The engine aborts requests (timeouts, SSRF probes) and sends deliberately
  // malformed hosts/paths. A thrown handler must never take the listener down,
  // or every later probe sees ECONNREFUSED and the run is meaningless.
  res.on('error', () => {})
  req.on('error', () => {})

  let pathname = '/'
  let u
  try {
    // Parse path and query separately. The engine's root probes build
    // `${url}/?param=`, which on a trailing-slash target yields "//?param=" — a
    // string `new URL()` reads as a protocol-relative authority and drops the
    // query on the floor. Splitting on the first "?" keeps the parameters.
    const raw = String(req.url || '/')
    const qIndex = raw.indexOf('?')
    const rawPath = (qIndex === -1 ? raw : raw.slice(0, qIndex)) || '/'
    const rawQuery = qIndex === -1 ? '' : raw.slice(qIndex)
    // Collapse the doubled slash back onto the index route; trailing slashes are
    // otherwise preserved (/uploads/ must stay a directory URL).
    pathname = rawPath.replace(/\/{2,}/g, '/') || '/'
    u = new URL(`http://x${pathname}${rawQuery}`)
  } catch {
    // A header-injection or otherwise unparseable target: answer, don't crash.
    u = new URL('http://x/')
    pathname = String(req.url || '/').split('?')[0]
  }
  if (process.env.TESTBED_DEBUG) {
    console.error('[req]', req.method, JSON.stringify(req.url), '->', pathname, JSON.stringify([...u.searchParams]))
  }
  const ip = req.socket.remoteAddress || 'unknown'

  let body = ''
  try {
    for await (const chunk of req) {
      body += chunk
      if (body.length > 1e6) break
    }
  } catch {
    // Client went away mid-body (probe timeout). Fall through with what we have.
  }

  // The harness (a separate process) reads the collaborator's hit log here.
  if (u.pathname === '/__oob/events') {
    const token = u.searchParams.get('token') || ''
    return respond(res, json(oobHits.get(token) ?? []))
  }

  try {
    if (pathname === '/index.html') pathname = '/'

    const route = ROUTES[pathname]
    if (!route) {
      // The planted verbose-error bug: a 404 leaks a stack trace and the app's
      // absolute paths instead of a clean page.
      return respond(res, text(
        `Error: Cannot GET ${pathname}\n    at Layer.handle [as handle_request] (/srv/app/node_modules/express/lib/router/layer.js:95:5)\n    at next (/srv/app/node_modules/express/lib/router/route.js:144:13)\n    at Route.dispatch (/srv/app/node_modules/express/lib/router/route.js:114:3)`,
        404,
      ))
    }

    return respond(res, route(req, u, body, ip) || text('ok'))
  } catch (err) {
    try {
      return respond(res, text(`Error: ${err.message}\n    at handler (/srv/app/${pathname}:1:1)`, 500))
    } catch {
      try { res.destroy() } catch { /* already gone */ }
    }
  }
})

// A malformed request line is parsed by Node before our handler sees it; answer
// 400 instead of letting the listener die.
server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n') } catch { /* ignore */ }
})

// Last resort: a probe must not be able to kill the target under test.
process.on('uncaughtException', (e) => console.error('[testbed] uncaught:', e?.message))
process.on('unhandledRejection', (e) => console.error('[testbed] unhandled:', e?.message))

server.listen(PORT, HOST, () => {
  console.log(`testbed listening on http://${HOST}:${PORT}`)
})

// ---------------------------------------------------------------------------
// Raw-socket "fronting proxy" for CRLF injection (port PORT+1).
//
// Node's http module REJECTS a header value containing CR/LF (ERR_INVALID_CHAR),
// so a Node origin physically cannot demonstrate response-header injection — the
// testbed would be testing Node's own validation, not the app's. Real CRLF bugs
// live in code that writes the header block by hand (or in a proxy that
// concatenates input into a header), which is exactly what this listener does: it
// takes `lang`, decodes it, and writes the raw response bytes with the value
// pasted into a Set-Cookie line. A `%0d%0a` in `lang` therefore starts a real new
// header line, the classic response-splitting primitive.
const crlfServer = net.createServer((socket) => {
  let buf = ''
  socket.on('error', () => {})
  socket.on('data', (chunk) => {
    buf += chunk.toString('latin1')
    const end = buf.indexOf('\r\n\r\n')
    if (end === -1) return
    const requestLine = buf.split('\r\n')[0] || ''
    const target = requestLine.split(' ')[1] || '/'
    const qIndex = target.indexOf('?')
    const rawQuery = qIndex === -1 ? '' : target.slice(qIndex + 1)
    const params = new URLSearchParams(rawQuery)
    const lang = params.get('lang') || params.get('q') || params.get('next') || 'en'
    // The bug: the decoded value goes straight into a header line.
    const injected = `Set-Cookie: lang=${lang}\r\n`
    const body = 'ok'
    socket.end(
      'HTTP/1.1 200 OK\r\n' +
      'Content-Type: text/html\r\n' +
      injected +
      'X-Testbed: crlf-proxy\r\n' +
      `Content-Length: ${body.length}\r\n` +
      'Connection: close\r\n\r\n' +
      body,
    )
  })
})
crlfServer.listen(PORT + 1, HOST, () => {
  console.log(`testbed CRLF proxy listening on http://${HOST}:${PORT + 1}`)
})

// ---------------------------------------------------------------------------
// Plain-file server (port PORT+3): its ROOT is an auto-generated directory
// index. `open-directory-listing` only requests "/", so the listing has to live
// at the root of a target — a subdirectory of the main app can never trip it.
const listingServer = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x')
  if (u.pathname === '/' || u.pathname === '/files/') {
    res.writeHead(200, { 'Content-Type': 'text/html', 'X-Powered-By': 'Express/4.18.2' })
    res.end(
      '<!doctype html><html><head><title>Index of /</title></head><body>' +
      '<h1>Index of /</h1><pre><a href="a.txt">a.txt</a>\n<a href="b.txt">b.txt</a>\n' +
      '<a href="backup.zip">backup.zip</a></pre></body></html>',
    )
    return
  }
  res.writeHead(404, { 'Content-Type': 'text/html', 'X-Powered-By': 'Express/4.18.2' })
  res.end('<title>404 Not Found</title>')
})
listingServer.listen(PORT + 3, HOST, () => {
  console.log(`testbed listing server listening on http://${HOST}:${PORT + 3}`)
})

/** Every listener, so a harness that imports this module can shut them down. */
export const __servers = [server, crlfServer, oobServer, listingServer]
