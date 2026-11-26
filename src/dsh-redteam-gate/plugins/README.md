# Two apps, two sections

SecScan and SecLayer are each a TypeScript/Node app with its own MCP server. They
are wired in as **two independent configuration-only bundles** — no shared code, no
merged engine, no interference. Each one owns its own `serverName`, transport,
credentials and tools.

| Section | Bundle | Transport | Endpoint / command | Tools |
|---|---|---|---|---|
| SecScan | `secscan-mcp` | `streamable-http` | `https://secscan.us/api/mcp` | `mcp__secscan__*` |
| SecLayer | `seclayer-mcp` | `stdio` | `npx -y @seclayer/mcp` | `mcp__seclayer__*` |

Each bundle is a `package.json` with `dsh.bundle.patch` and a
`cordis.patch.yml` that inserts `@deepseek-ai/dsh-mcp-client`. That is the whole
mechanism: DSH asks each app's own MCP server for its tools, and namespaces them by
`serverName`, so the two can never collide.

## Credentials

Neither server is reachable without its key, and neither key is written here. Both
bundles use `expandTemplates: true` and reference the value as
`${credential:NAME}`, which also makes the client redact every resolved value from
diagnostics:

- `SECSCAN_API_TOKEN` — a SecScan API token, sent as `Authorization: Bearer …`
- `SECLAYER_API_KEY` — a Seclayer API key, passed as `SECLAYER_API_KEY`
- `SECLAYER_API_URL` — optional, defaults to `https://seclayer.app`

Until a key resolves, that section stays **disconnected** and every other section
keeps working: both entries set `failOnStartupError: false` deliberately, so a
missing key costs one section and never the profile.

## Install

```
plugin_manager install_bundle target="link:<this dir>/seclayer-mcp"
plugin_manager install_bundle target="link:<this dir>/secscan-mcp"
```

Both are installed in the `web` profile and take effect without a restart
(`application: applied`).
