import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchResponse, runTemplate, runTemplates, Template, ResponseView } from './templateEngine.js';
import { TEMPLATES } from './templates.js';

const view = (o: Partial<ResponseView>): ResponseView => ({ status: 200, body: '', headers: '', ...o });

test('status matcher', () => {
  assert.equal(matchResponse([{ type: 'status', status: [200, 204] }], 'and', view({ status: 200 })), true);
  assert.equal(matchResponse([{ type: 'status', status: [200] }], 'and', view({ status: 404 })), false);
});

test('word matcher with or/and conditions', () => {
  const r = view({ body: 'services:\n image: nginx' });
  assert.equal(matchResponse([{ type: 'word', words: ['services:', 'nope'], condition: 'or' }], 'and', r), true);
  assert.equal(matchResponse([{ type: 'word', words: ['services:', 'image:'], condition: 'and' }], 'and', r), true);
  assert.equal(matchResponse([{ type: 'word', words: ['services:', 'absent'], condition: 'and' }], 'and', r), false);
});

test('negative matcher excludes SPA html fallback', () => {
  const spa = view({ status: 200, body: '<!doctype html><html><head></head></html>' });
  const m = [
    { type: 'status' as const, status: [200] },
    { type: 'word' as const, words: ['FROM '] },
    { type: 'word' as const, words: ['<!doctype', '<html'], negative: true },
  ];
  assert.equal(matchResponse(m, 'and', spa), false); // html present -> negative fails -> no match
  const real = view({ status: 200, body: 'FROM node:22\nRUN npm ci' });
  assert.equal(matchResponse(m, 'and', real), true);
});

test('regex and header part matchers', () => {
  assert.equal(matchResponse([{ type: 'regex', regex: '^[A-Z_]+=' }], 'and', view({ body: 'DB_PASSWORD=secret' })), true);
  assert.equal(
    matchResponse([{ type: 'word', part: 'header', words: ['x-powered-by'] }], 'and', view({ headers: 'x-powered-by: php\n' })),
    true,
  );
});

test("matchersCondition 'or' matches when any matcher passes", () => {
  const r = view({ status: 500, body: 'Adminer' });
  assert.equal(matchResponse([{ type: 'status', status: [200] }, { type: 'word', words: ['Adminer'] }], 'or', r), true);
});

test('runTemplate returns a finding only on a real match', async () => {
  const tpl: Template = {
    id: 't', name: 'Test Panel', severity: 'high', category: 'DAST',
    description: 'desc', fix: 'fix',
    requests: [{ path: '/panel', matchers: [{ type: 'status', status: [200] }, { type: 'word', words: ['SECRET_PANEL'] }] }],
  };
  const hit: any = async () => new Response('...SECRET_PANEL...', { status: 200, headers: { 'content-type': 'text/plain' } });
  const miss: any = async () => new Response('<!doctype html>', { status: 200, headers: { 'content-type': 'text/html' } });
  const f = await runTemplate(tpl, 'https://app.test', hit);
  assert.ok(f && f.title === 'Test Panel' && f.severity === 'high');
  assert.equal(await runTemplate(tpl, 'https://app.test', miss), null);
});

test('runTemplates aggregates across the pack', async () => {
  // Respond as an exposed docker-compose for every request.
  const fetchFn: any = async (url: string) =>
    url.endsWith('/docker-compose.yml')
      ? new Response('version: "3"\nservices:\n web:\n  image: nginx', { status: 200, headers: { 'content-type': 'text/yaml' } })
      : new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } });
  const findings = await runTemplates('https://app.test', fetchFn, TEMPLATES);
  assert.ok(findings.some((f) => /docker-compose/i.test(f.title)));
});

test('backup-archive template fires on a zip content-type, not on an HTML page', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'backup-archive-exposed')!;
  const zip: any = async () => new Response('PK\x03\x04', { status: 200, headers: { 'content-type': 'application/zip' } });
  const html: any = async () => new Response('<!doctype html>', { status: 200, headers: { 'content-type': 'text/html' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', zip));
  assert.equal(await runTemplate(tpl, 'https://app.test', html), null);
});

test('htpasswd template regex matches a hashed credential line', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'htpasswd-exposed')!;
  const hit: any = async () => new Response('admin:$apr1$xyz$abcdef', { status: 200, headers: { 'content-type': 'text/plain' } });
  const miss: any = async () => new Response('just some text', { status: 200, headers: { 'content-type': 'text/plain' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', hit));
  assert.equal(await runTemplate(tpl, 'https://app.test', miss), null);
});

test('wp user-enumeration requires both slug and name (and condition)', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'wp-user-enumeration')!;
  const users: any = async () => new Response('[{"id":1,"name":"Admin","slug":"admin"}]', { status: 200, headers: { 'content-type': 'application/json' } });
  const partial: any = async () => new Response('{"slug":"x"}', { status: 200, headers: { 'content-type': 'application/json' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', users));
  assert.equal(await runTemplate(tpl, 'https://app.test', partial), null);
});

test('subdomain-takeover fires on a service fingerprint at root', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'subdomain-takeover')!;
  const dangling: any = async () => new Response("There isn't a GitHub Pages site here.", { status: 404, headers: { 'content-type': 'text/html' } });
  const normal: any = async () => new Response('<!doctype html><html>Welcome</html>', { status: 200, headers: { 'content-type': 'text/html' } });
  assert.ok(await runTemplate(tpl, 'https://sub.app.test', dangling));
  assert.equal(await runTemplate(tpl, 'https://sub.app.test', normal), null);
});

test('subdomain-takeover does NOT fire on a live site that merely references herokucdn.com as a CDN asset host', async () => {
  // Regression for a live false positive: heroku.com's own real homepage
  // (a 200 response) includes <link rel="preconnect" href="https://www.herokucdn.com">
  // as an ordinary resource hint, which the old bare "herokucdn.com" word
  // matched even though the page is nothing like the actual "no such app"
  // dangling-resource page. Confirmed during the 2026-09-28 live-site sweep.
  const tpl = TEMPLATES.find((t) => t.id === 'subdomain-takeover')!;
  const liveHerokuSite: any = async () =>
    new Response('<!doctype html><html><head><link rel="preconnect" href="https://www.herokucdn.com"></head><body>Welcome</body></html>', {
      status: 200,
      headers: { 'content-type': 'text/html' },
    });
  assert.equal(await runTemplate(tpl, 'https://www.heroku.com', liveHerokuSite), null);
});

test('netrc template regex matches machine login/password', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'netrc-exposed')!;
  const hit: any = async () => new Response('machine api.example.com login bob password s3cret', { status: 200, headers: { 'content-type': 'text/plain' } });
  const miss: any = async () => new Response('nothing to see', { status: 200, headers: { 'content-type': 'text/plain' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', hit));
  assert.equal(await runTemplate(tpl, 'https://app.test', miss), null);
});

test('kibana-exposed template fires on a real Kibana bootstrap page, not on an SPA that echoes the request path', async () => {
  // Regression for a live false positive: netflix.com/reddit.com's SPA
  // catch-all shell at /app/kibana returned 200 and, on reddit.com, the
  // literal word "kibana" (the request path's own last segment, echoed back
  // in ordinary shell HTML). "kbn-injected-metadata" is Kibana's actual
  // bootstrap script id and only appears in a genuine Kibana app shell.
  const tpl = TEMPLATES.find((t) => t.id === 'kibana-exposed')!;
  const realKibana: any = async () =>
    new Response('<kbn-injected-metadata data="..."></kbn-injected-metadata>', { status: 200, headers: { 'content-type': 'text/html' } });
  const spaEchoingPath: any = async () =>
    new Response('<!doctype html><html><head><link rel="canonical" href="https://www.reddit.com/app/kibana"></head><body>Reddit</body></html>', {
      status: 200,
      headers: { 'content-type': 'text/html' },
    });
  assert.ok(await runTemplate(tpl, 'https://app.test', realKibana));
  assert.equal(await runTemplate(tpl, 'https://app.test', spaEchoingPath), null);
});

test('phpmyadmin template fires on a real login page, not on a multi-tenant catch-all profile page', async () => {
  // Regression for a live false positive: github.com/phpmyadmin/ is the real
  // phpMyAdmin project's GitHub org page -- a normal 200 whose body legitimately
  // says "phpMyAdmin" two dozen times (org name, repo names, bio). Only the
  // login form's actual field name (pma_username) may fire this template.
  const tpl = TEMPLATES.find((t) => t.id === 'phpmyadmin-exposed')!;
  const realLogin: any = async () =>
    new Response('<form><input name="pma_username"><input name="pma_password"></form>', { status: 200, headers: { 'content-type': 'text/html' } });
  const githubOrgCatchAll: any = async () =>
    new Response('<title>phpMyAdmin · GitHub</title><body>phpMyAdmin phpMyAdmin/phpmyadmin phpMyAdmin Team</body>', { status: 200, headers: { 'content-type': 'text/html' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', realLogin));
  assert.equal(await runTemplate(tpl, 'https://app.test', githubOrgCatchAll), null);
});

test('graphiql template fires on a real GraphiQL/Playground mount, not on a multi-tenant catch-all profile page', async () => {
  // Regression for two live false positives:
  //  - github.com/graphiql is a real GitHub org/user by that name --
  //    "graphiql" appears dozens of times in ordinary profile-page content
  //    (nav, repo names, links), but never the app's actual DOM mount point.
  //  - gitlab.com/graphiql is likewise a real group page, and GitLab's own
  //    template stamps the slug into `data-page-type-id="graphiql"` on the
  //    <body> tag -- a naive substring check on `id="graphiql"` matches that
  //    too, since it's a substring of `-type-id="graphiql"`. Only an actual
  //    `<div id="graphiql">` element may fire this template.
  const tpl = TEMPLATES.find((t) => t.id === 'graphiql-exposed')!;
  const realGraphiql: any = async () =>
    new Response('<html><body><div id="graphiql">Loading...</div></body></html>', { status: 200, headers: { 'content-type': 'text/html' } });
  const realGraphiqlOtherAttrsFirst: any = async () =>
    new Response('<html><body><div class="app" id="graphiql">Loading...</div></body></html>', { status: 200, headers: { 'content-type': 'text/html' } });
  const githubOrgCatchAll: any = async () =>
    new Response('<title>graphiql · GitHub</title><body>graphiql graphiql/graphiql GraphiQL is here</body></html>', { status: 200, headers: { 'content-type': 'text/html' } });
  const gitlabGroupCatchAll: any = async () =>
    new Response('<body class="tab-width-8" data-group="graphiql" data-page-type-id="graphiql">graphiql</body>', { status: 200, headers: { 'content-type': 'text/html' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', realGraphiql));
  assert.ok(await runTemplate(tpl, 'https://app.test', realGraphiqlOtherAttrsFirst));
  assert.equal(await runTemplate(tpl, 'https://app.test', githubOrgCatchAll), null);
  assert.equal(await runTemplate(tpl, 'https://app.test', gitlabGroupCatchAll), null);
});

test('shipped templates are well-formed', () => {
  const cats = new Set(['DAST', 'SAST', 'IAST', 'SCA', 'EASM', 'RED_TEAM']);
  const ids = new Set<string>();
  for (const t of TEMPLATES) {
    assert.ok(t.id && !ids.has(t.id), `unique id: ${t.id}`);
    ids.add(t.id);
    assert.ok(t.name && t.description && t.fix);
    assert.ok(cats.has(t.category), `valid category: ${t.category}`);
    assert.ok(t.requests.length > 0 && t.requests.every((r) => r.path && r.matchers.length > 0));
  }
});

test('a challenge page that echoes the requested path is not an exposed Swagger UI', async () => {
  // Shape of reddit's bot-challenge response: 200, and the path reflected in a form action.
  const echo = (u: string) => new URL(u).pathname;
  const challenge = async (u: string) =>
    new Response(`<html><title>Reddit</title><form hidden method="GET" action="${echo(u)}"><input name="solution"></form></html>`, { status: 200 });
  const swagger = TEMPLATES.find((x) => x.id === 'swagger-ui-exposed')!;
  assert.equal(await runTemplate(swagger, 'https://example.com', challenge), null);
  const jolokia = TEMPLATES.find((x) => x.id === 'jolokia-exposed')!;
  assert.equal(await runTemplate(jolokia, 'https://example.com', challenge), null);
});

test('a real Swagger UI page still matches once the path echo is removed', async () => {
  const real = async (u: string) =>
    new Response(`<html><title>Swagger UI</title><link rel="stylesheet" href="./swagger-ui.css"><script src="./swagger-ui-bundle.js"></script><!-- ${new URL(u).pathname} --></html>`, { status: 200 });
  const swagger = TEMPLATES.find((x) => x.id === 'swagger-ui-exposed')!;
  const f = await runTemplate(swagger, 'https://example.com', real);
  assert.equal(f?.title, 'Swagger UI Exposed');
});

test('path-echo scrubbing leaves words unrelated to the path alone', () => {
  const dirListing = { status: 200, body: '<title>Index of /backup/</title>', headers: '', requestPath: '/backup/' };
  assert.equal(matchResponse([{ type: 'word', words: ['Index of /'] }], 'and', dirListing), true);
});

// --- False-positive regressions from the 2026-10-09 audit -------------------
// Each pairs the benign response that used to fire with the real exposure the
// template exists for, so tightening a matcher can never silently blind it.
const tplById = (id: string) => TEMPLATES.find((t) => t.id === id)!;
const respond = (body: string | Uint8Array, contentType: string, status = 200): any => async () =>
  new Response(body, { status, headers: { 'content-type': contentType } });

test("spring-actuator-health ignores Spring's default status-only answer", async () => {
  const tpl = tplById('spring-actuator-health');
  const json = 'application/vnd.spring-boot.actuator.v3+json';
  assert.equal(await runTemplate(tpl, 'https://app.test', respond('{"status":"UP"}', json)), null);
  assert.equal(await runTemplate(tpl, 'https://app.test', respond('{"status":"UP","groups":["liveness","readiness"]}', json)), null);
  const details = '{"status":"UP","components":{"db":{"status":"UP","details":{"database":"PostgreSQL"}},"diskSpace":{"status":"UP"}}}';
  assert.ok(await runTemplate(tpl, 'https://app.test', respond(details, json)));
});

test('laravel-telescope needs Telescope itself, not a Laravel app answering the path', async () => {
  const tpl = tplById('laravel-telescope');
  // Route::view('/{any}', 'app') with the framework's default APP_NAME.
  const laravelShell = '<!DOCTYPE html><html><head><title>Laravel</title><script type="module" src="/build/assets/app-4ed993c7.js"></script></head><body><div id="app"></div></body></html>';
  assert.equal(await runTemplate(tpl, 'https://app.test', respond(laravelShell, 'text/html')), null);
  const telescope = '<!DOCTYPE html><html><head><title>Telescope - Laravel</title><link rel="shortcut icon" href="/vendor/telescope/favicon.ico"></head><body><div id="telescope" v-cloak></div><script>window.Telescope = {"path":"telescope","timezone":"UTC","recording":true};</script><script src="/vendor/telescope/app.js?id=7049e92a398e816f8cd53a915eaea592"></script></body></html>';
  assert.ok(await runTemplate(tpl, 'https://app.test', respond(telescope, 'text/html')));
});

test('backup-archive needs an archive in the body, not just a binary content type', async () => {
  const tpl = tplById('backup-archive-exposed');
  assert.equal(await runTemplate(tpl, 'https://app.test', respond('', 'application/octet-stream')), null);
  assert.equal(await runTemplate(tpl, 'https://app.test', respond('{"error":"not found"}', 'application/octet-stream')), null);
  // An archive signature only counts at the very start of the body.
  assert.equal(await runTemplate(tpl, 'https://app.test', respond('log line\nPK\x03\x04', 'application/octet-stream')), null);
  const gzip = new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
  const gzOnly: any = async (u: string) =>
    u.endsWith('.tar.gz') ? new Response(gzip, { status: 200, headers: { 'content-type': 'application/gzip' } }) : new Response('', { status: 404 });
  assert.ok(await runTemplate(tpl, 'https://app.test', gzOnly));
});

test('grafana-exposed needs a Grafana boot page, not a login page that names Grafana', async () => {
  const tpl = tplById('grafana-exposed');
  const saasLogin = '<!doctype html><html><head><title>Sign in · Acme Monitor</title></head><body><form action="/session" method="post"><input name="email"><input name="password" type="password"></form><p>Works with Datadog, Grafana and Prometheus.</p></body></html>';
  assert.equal(await runTemplate(tpl, 'https://app.test', respond(saasLogin, 'text/html')), null);
  const grafana = '<!DOCTYPE html><html lang="en"><head><title>Grafana</title></head><body class="theme-dark app-grafana"><div id="reactRoot"></div><script nonce="">window.grafanaBootData = { user: {}, settings: {}, navTree: [] };</script></body></html>';
  assert.ok(await runTemplate(tpl, 'https://app.test', respond(grafana, 'text/html')));
});

test('jolokia, configprops, docker-compose and sftp templates need their file shape, not one common key', async () => {
  const cases: Array<[string, string, string, string]> = [
    ['jolokia-exposed', '{"request":"/jolokia/list","error":"route not found"}',
      '{"request":{"type":"list"},"value":{"JMImplementation":{"type=MBeanServerDelegate":{}},"java.lang":{"type=Runtime":{}}},"status":200}', 'application/json'],
    ['actuator-configprops-exposed', '{"prefix":"/api","routes":[]}',
      '{"contexts":{"application":{"beans":{"spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties":{"prefix":"spring.datasource","properties":{}}}}}}', 'application/json'],
    ['docker-compose-exposed', 'version: 4.2.1\nstatus: ok\n',
      'services:\n  web:\n    build: .\n  db:\n    image: postgres:16\n', 'text/yaml'],
    ['vscode-sftp-exposed', '{"host":"app.test","path":"/.vscode/sftp.json","status":"ok"}',
      '{"name":"prod","host":"203.0.113.7","protocol":"sftp","port":22,"username":"deploy","remotePath":"/var/www"}', 'application/json'],
  ];
  for (const [id, benign, real, type] of cases) {
    assert.equal(await runTemplate(tplById(id), 'https://app.test', respond(benign, type)), null, `${id} benign`);
    assert.ok(await runTemplate(tplById(id), 'https://app.test', respond(real, type)), `${id} real`);
  }
});

test('rails-info needs the properties table, not a page that mentions middleware', async () => {
  const tpl = tplById('rails-info-exposed');
  assert.equal(await runTemplate(tpl, 'https://app.test', respond('<html><body><h1>Our Middleware Guide</h1></body></html>', 'text/html')), null);
  const props = '<table><tr><td>Rails version</td><td>7.1.3</td></tr><tr><td>Ruby version</td><td>3.3.0</td></tr><tr><td>Middleware</td><td>ActionDispatch::HostAuthorization</td></tr></table>';
  assert.ok(await runTemplate(tpl, 'https://app.test', respond(props, 'text/html')));
});

test('a public OpenAPI spec is informational, and a bare "openapi" key is not a spec', async () => {
  const tpl = tplById('openapi-spec-exposed');
  assert.equal(tpl.severity, 'info');
  assert.equal(await runTemplate(tpl, 'https://app.test', respond('{"openapi":"unsupported route"}', 'application/json')), null);
  const spec = '{"openapi":"3.1.0","info":{"title":"Public API","version":"1"},"paths":{"/v1/things":{}}}';
  assert.equal((await runTemplate(tpl, 'https://app.test', respond(spec, 'application/json')))?.severity, 'info');
});
