window.__ModuleLoader__.load({
  id: '@local/seclayer-panel',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    // Both local scanners, each on its own loopback port. The app is the
    // interface: its dashboard lists scans, an in-progress scan shows the live
    // ticker, and a finished one opens its own report page. Nothing here
    // re-renders any of that — the Browser tab loads the app itself.
    const APPS = [
      { key: 'seclayer', name: 'Seclayer', url: 'http://127.0.0.1:4710', hint: 'SecLayer via view proxy 4710 — scans, live progress, reports' },
      { key: 'secscan', name: 'Secscan', url: 'http://127.0.0.1:4711', hint: 'SecScan via view proxy 4711 — scans, monitors, reports' },
    ];

    const btn = {
      font: 'inherit', fontSize: 12, lineHeight: 1.2, cursor: 'pointer',
      padding: '4px 10px', borderRadius: 6, border: '1px solid var(--border, #33333a)',
      background: 'transparent', color: 'var(--fg, #e6e6ea)',
    };

    function ScannerBar() {
      const open = ScannerBar.open;
      return h('div', {
        style: { display: 'flex', gap: 6, alignItems: 'center', padding: '2px 0' },
      },
        h('span', { style: { fontSize: 11, opacity: 0.6, marginRight: 2 } }, 'Scanners'),
        APPS.map((app) =>
          h('button', {
            key: app.key,
            type: 'button',
            style: btn,
            title: app.hint,
            onClick: () => open(app.url + '/'),
          }, app.name),
        ),
      );
    }

    // Scan tools of the two apps. When the agent runs one of these, the app opens
    // by itself in the Browser tab: the dashboard (live ticker) as the scan starts,
    // and the app's own report page when it finishes. `starts` marks the tools that
    // begin a scan. Calls that are already finished when the row first renders
    // (reopening an old session) never auto-open; they only offer the button.
    const SCAN_TOOLS = {
      mcp__seclayer__seclayer_scan: { app: 'seclayer', starts: true },
      mcp__seclayer__seclayer_get_report: { app: 'seclayer', starts: false },
      mcp__secscan__scan_url: { app: 'secscan', starts: true },
      mcp__secscan__get_scan_status: { app: 'secscan', starts: false },
      mcp__secscan__get_report: { app: 'secscan', starts: false },
    };
    const autoOpened = new Set();

    function resultText(block) {
      if (!block || !Array.isArray(block.content)) return '';
      return block.content.map((c) => (c && c.type === 'text' ? c.text : '')).join('\n');
    }

    // SecScan reports live at /report/<scanId>; SecLayer's report is shown from its dashboard.
    function reportUrl(app, text) {
      if (app.key === 'secscan') {
        // A finished scan's tool text carries "Full report: <origin>/report/<reportId>". The
        // report id is NOT the scan_id the start call returns, so a scan_id is never turned
        // into a report link: until the Full report line exists the dashboard is opened.
        const m = /\/report\/([0-9a-f-]{36})/i.exec(text);
        if (m) return app.url + '/report/' + m[1];
      }
      return app.url + '/';
    }

    function ScanToolRow(props) {
      const spec = SCAN_TOOLS[props.toolName];
      const app = APPS.find((a) => a.key === spec.app);
      const phase = props.phase;
      const text = phase === 'result' ? resultText(props.block) : '';
      const url = phase === 'result' ? reportUrl(app, text) : app.url + '/';
      const live = React.useRef(phase !== 'result');
      React.useEffect(() => {
        if (!live.current || phase === 'preparing') return;
        const stage = phase === 'start' ? 'start' : 'result';
        if (stage === 'start' && !spec.starts) return;
        const key = props.callId + ':' + stage;
        if (autoOpened.has(key)) return;
        autoOpened.add(key);
        ScannerBar.open(url);
      }, [phase, url]);
      const failed = phase === 'result' && props.block && props.block.isError;
      const status = phase === 'result' ? (failed ? 'failed' : 'finished') : 'running';
      return h('div', { style: { fontSize: 12, padding: '4px 0' }, 'data-tool': props.toolName, 'data-state': status },
        h('span', null, app.name + ' ' + props.toolName.split('__').pop() + ' — ' + status + ' '),
        h('button', { type: 'button', style: btn, onClick: () => ScannerBar.open(url) },
          phase === 'result' && url !== app.url + '/' ? 'Open report' : 'Open ' + app.name),
        text ? h('details', { style: { marginTop: 4 } },
          h('summary', { style: { cursor: 'pointer', opacity: 0.7 } }, 'Result'),
          h('pre', { style: { whiteSpace: 'pre-wrap', fontSize: 11, maxHeight: 240, overflow: 'auto' } }, text)) : null,
      );
    }

    return {
      inject: ['slots', 'sidebarRight'],
      apply(ctx) {
        // One place that knows how to open a Browser tab; fall back to a normal
        // tab so the control never becomes a dead button.
        ScannerBar.open = (url) => {
          try {
            ctx.sidebarRight.openTab('browser', { params: { url } });
          } catch {
            window.open(url, '_blank', 'noopener');
          }
        };
        ctx.effect(() => ctx.slots.inject('conversation.composer.dock', () => ctx.slots.register({
          name: 'conversation.composer.dock', id: 'seclayer-panel', order: 5,
        }, ScannerBar)), 'seclayer-panel.slot');
        for (const name of Object.keys(SCAN_TOOLS)) {
          ctx.effect(() => ctx.slots.inject('tool.call.toolview', () => ctx.slots.register(
            { name: 'tool.call.toolview', key: name }, ScanToolRow,
          )), 'seclayer-panel.toolview.' + name);
        }
      },
    };
  },
});
