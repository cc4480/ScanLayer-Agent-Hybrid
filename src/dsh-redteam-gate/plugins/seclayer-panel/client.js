window.__ModuleLoader__.load({
  id: '@local/seclayer-panel',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    // The local SecLayer instance. The app itself is the interface: its dashboard
    // lists scans, its scan view is the live ticker, and /r/<token> is the report.
    // Nothing here re-renders any of that — the Browser tab loads the app.
    const APP = 'http://127.0.0.1:4700';

    const btn = {
      font: 'inherit', fontSize: 12, lineHeight: 1.2, cursor: 'pointer',
      padding: '4px 10px', borderRadius: 6, border: '1px solid var(--border, #33333a)',
      background: 'transparent', color: 'var(--fg, #e6e6ea)',
    };

    function SecLayerBar() {
      // Provided by the host through the slot; when absent, fall back to a new
      // tab so the control never becomes a dead button.
      const open = SecLayerBar.open;
      const go = (path) => () => open(APP + path);
      return h('div', {
        style: { display: 'flex', gap: 6, alignItems: 'center', padding: '2px 0' },
      },
        h('span', { style: { fontSize: 11, opacity: 0.6, marginRight: 2 } }, 'SecLayer'),
        h('button', { type: 'button', style: btn, onClick: go('/'), title: 'Scans, live progress and reports' }, 'Dashboard'),
        h('button', { type: 'button', style: btn, onClick: go('/'), title: 'Scans in progress show their live ticker' }, 'Live scans'),
      );
    }

    return {
      inject: ['slots', 'sidebarRight'],
      apply(ctx) {
        // One place that knows how to open a Browser tab.
        SecLayerBar.open = (url) => {
          try {
            ctx.sidebarRight.openTab('browser', { params: { url } });
          } catch {
            window.open(url, '_blank', 'noopener');
          }
        };
        ctx.effect(() => ctx.slots.inject('conversation.composer.dock', () => ctx.slots.register({
          name: 'conversation.composer.dock', id: 'seclayer-panel', order: 5,
        }, SecLayerBar)), 'seclayer-panel.slot');
      },
    };
  },
});
