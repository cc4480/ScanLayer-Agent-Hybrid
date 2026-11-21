// Local vulnerable lab for the SecLayer module tests. Binds 127.0.0.1 only and simulates each
// vulnerable behaviour in-process. Routes are chosen by the first path segment:
//   /vuln/*    reflects q unescaped, raw SQL error on a quote in id, SSH banner for url=127.0.0.1:22,
//              arithmetic/id output for ping
//   /json/*    reflects q inside a JSON body (not executable)
//   /escaped/* reflects q HTML-escaped (not exploitable)
//   /docs/*    static page that quotes an SQL error and an SSH banner for every request (false-positive control)

import http from 'node:http'

const SQL_ERR = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version'
const SSH_BANNER = 'SSH-2.0-OpenSSH_8.9p1 Lab'
const DOCS_PAGE = `<html><body><h1>Docs</h1><pre>${SQL_ERR}\n${SSH_BANNER}</pre></body></html>`

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

function vuln(url, send) {
  const p = url.searchParams
  if (p.has('q')) return send(200, 'text/html', `<html><body><h1>Results</h1><div>${p.get('q')}</div></body></html>`)
  if (p.has('id')) {
    if (p.get('id').includes("'")) return send(500, 'text/plain', SQL_ERR)
    return send(200, 'text/html', `<p>Item ${escapeHtml(p.get('id'))}</p>`)
  }
  if (p.has('url')) {
    if (p.get('url').includes('127.0.0.1:22')) return send(200, 'text/plain', `${SSH_BANNER}\n`)
    return send(200, 'text/plain', 'fetched')
  }
  if (p.has('ping')) {
    const ping = p.get('ping')
    const m = /expr (\d+) \+ (\d+)/.exec(ping)
    if (m) return send(200, 'text/plain', `127.0.0.1\n${Number(m[1]) + Number(m[2])}`)
    if (/;\s*id\b/.test(ping)) return send(200, 'text/plain', 'uid=1000(lab) gid=1000(lab)')
    return send(200, 'text/plain', 'PING 127.0.0.1')
  }
  return send(200, 'text/html', '<html><body><h1>Lab home</h1></body></html>')
}

/** Start the lab on an ephemeral 127.0.0.1 port. Returns { base, close }. */
export function startLabServer() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1')
    const send = (status, type, body) => {
      res.writeHead(status, { 'content-type': type })
      res.end(body)
    }
    switch (url.pathname.split('/')[1]) {
      case 'vuln':
        return vuln(url, send)
      case 'json':
        return send(200, 'application/json', JSON.stringify({ q: url.searchParams.get('q') ?? '' }))
      case 'escaped':
        return send(200, 'text/html', `<html><body>${escapeHtml(url.searchParams.get('q') ?? '')}</body></html>`)
      case 'docs':
        return send(200, 'text/html', DOCS_PAGE)
      default:
        return send(404, 'text/plain', 'not found')
    }
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({
        base: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}
