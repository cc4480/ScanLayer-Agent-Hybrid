import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isSourceMap, extractScriptSrcs, extractSourceMappingUrls, consolidateSourceMaps, embedsSourceText } from './sourceMapProbe.js';

test('isSourceMap accepts a real Source Map v3 and rejects the SPA HTML fallback', () => {
  const real = JSON.stringify({ version: 3, file: 'app.js', sources: ['src/app.ts'], sourcesContent: ['const x=1'], mappings: 'AAAA,SAAS' });
  assert.equal(isSourceMap(real), true);
  assert.equal(isSourceMap('<!doctype html><html><body>app</body></html>'), false);
  // JSON that merely has a "version" but is not a source map must not match.
  assert.equal(isSourceMap('{"version":"1.0.0","name":"app"}'), false);
  assert.equal(isSourceMap(''), false);
});

test('extractScriptSrcs returns same-origin JS bundles, resolving relative URLs', () => {
  const html = `
    <script src="/assets/index-abc123.js"></script>
    <script src="https://target.test/vendor.mjs"></script>
    <script src="https://cdn.other.com/analytics.js"></script>
    <script>inline()</script>`;
  const srcs = extractScriptSrcs(html, 'https://target.test/');
  assert.ok(srcs.includes('https://target.test/assets/index-abc123.js'), 'relative → absolute same-origin');
  assert.ok(srcs.includes('https://target.test/vendor.mjs'), 'absolute same-origin .mjs');
  assert.ok(!srcs.some((s) => s.includes('cdn.other.com')), 'cross-origin bundle excluded');
});

test('extractSourceMappingUrls resolves a same-origin comment ref and skips inline data: maps', () => {
  const js = 'console.log(1)\n//# sourceMappingURL=index-abc123.js.map\n';
  const urls = extractSourceMappingUrls(js, 'https://target.test/assets/index-abc123.js');
  assert.deepEqual(urls, ['https://target.test/assets/index-abc123.js.map']);
  // Inline base64 maps are already in the bundle — not separately exposed.
  assert.deepEqual(extractSourceMappingUrls('x\n//# sourceMappingURL=data:application/json;base64,eyJ9\n', 'https://target.test/a.js'), []);
});

test('several exposed maps collapse into one finding that still names every file', () => {
  const mk = (path: string) => ({ path, status: 200, exposed: true, meta: { title: `Exposed JavaScript source map (${path})`, severity: 'low' as const, description: 'd', fix: 'f' } });
  const one = consolidateSourceMaps([mk('/a.js.map')]);
  assert.equal(one.length, 1);
  assert.equal(one[0].meta.title, 'Exposed JavaScript source map (/a.js.map)', 'a single map keeps its original title');

  const many = consolidateSourceMaps(['/a.js.map', '/b.js.map', '/c.js.map', '/d.js.map', '/e.js.map'].map(mk));
  assert.equal(many.length, 1, 'one finding, scored once');
  assert.equal(many[0].meta.title, 'Exposed JavaScript source maps (5 files)');
  for (const p of ['/a.js.map', '/e.js.map']) assert.ok(many[0].meta.description.includes(p));
  assert.equal(many[0].meta.severity, 'low');
  assert.deepEqual(consolidateSourceMaps([]), []);
});

test('a map without sourcesContent is described as file names only, not as the real code', () => {
  const namesOnly = JSON.stringify({ version: 3, sources: ['src/App.tsx', 'src/api.ts'], names: [], mappings: 'AAAA' });
  const withSource = JSON.stringify({ version: 3, sources: ['src/App.tsx'], sourcesContent: ['export const App = () => null;'], mappings: 'AAAA' });
  const placeholders = JSON.stringify({ version: 3, sources: ['src/App.tsx'], sourcesContent: [null, ''], mappings: 'AAAA' });
  assert.equal(embedsSourceText(namesOnly), false);
  assert.equal(embedsSourceText(placeholders), false);
  assert.equal(embedsSourceText(withSource), true);

  const mk = (path: string, embedsSource: boolean) =>
    ({ path, status: 200, exposed: true, embedsSource, meta: { title: 't', severity: 'low' as const, description: 'd', fix: 'f' } });
  const none = consolidateSourceMaps([mk('/a.js.map', false), mk('/b.js.map', false)])[0];
  assert.match(none.meta.description, /do not embed their contents/);
  assert.doesNotMatch(none.meta.description, /your real code/);
  const mixed = consolidateSourceMaps([mk('/a.js.map', true), mk('/b.js.map', false)])[0];
  assert.match(mixed.meta.description, /1 of them embed the original source text/);
  const all = consolidateSourceMaps([mk('/a.js.map', true), mk('/b.js.map', true)])[0];
  assert.match(all.meta.description, /your real code/);
});
