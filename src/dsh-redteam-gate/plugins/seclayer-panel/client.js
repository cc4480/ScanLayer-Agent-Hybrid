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
      },
    };
  },
});
