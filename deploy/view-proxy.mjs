// Loopback-only view proxy for DSH's Browser panel.
//
// The apps send `X-Frame-Options: DENY` and `Content-Security-Policy:
// frame-ancestors 'none'`, which is correct hardening for a public deployment but
// means a Browser tab can never embed them. This proxy serves the SAME app on a
// different loopback port with only those two framing refusals removed - nothing
// else is touched, and it listens on 127.0.0.1 only.
//
// It is our tooling, not a change to either app: no fork, no patch.
//
//   127.0.0.1:4710  ->  SecLayer  127.0.0.1:4700
//   127.0.0.1:4711  ->  SecScan   127.0.0.1:4701
//
// Run detached; deploy/stack-up.ps1 starts it when it is not listening.

import http from 'node:http'

const ROUTES = [
  { port: 4710, target: 'http://127.0.0.1:4700', name: 'SecLayer' },
  { port: 4711, target: 'http://127.0.0.1:4701', name: 'SecScan' },
]

// Drop the two headers that refuse framing; keep every other security header.
function relax(headers) {
  const out = { ...headers }
  delete out['x-frame-options']
  const csp = out['content-security-policy']
  if (typeof csp === 'string') {
    out['content-security-policy'] = csp
      .split(';')
      .map((d) => d.trim())
      .filter((d) => d && !/^frame-ancestors\b/i.test(d))
      .join('; ')
  }
  return out
}

function start({ port, target, name }) {
  const upstream = new URL(target)

  const server = http.createServer((req, res) => {
    const path = req.url || '/'
    const proxyReq = http.request(
      {
        host: upstream.hostname,
        port: upstream.port,
        method: req.method,
        path,
        headers: { ...req.headers, host: `${upstream.hostname}:${upstream.port}` },
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 502, relax(proxyRes.headers))
        proxyRes.pipe(res)
      },
    )
    proxyReq.on('error', (err) => {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`${name} is not reachable at ${target}: ${err.message}\n`)
    })
    req.pipe(proxyReq)
  })

  server.listen(port, '127.0.0.1', () => {
    console.log(`[view-proxy] ${name}  http://127.0.0.1:${port}  ->  ${target}`)
  })
  server.on('error', (err) => {
    console.error(`[view-proxy] ${name} could not listen on ${port}: ${err.message}`)
    process.exitCode = 1
  })
}

for (const route of ROUTES) start(route)
