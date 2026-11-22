import { defineConfig } from 'tsdown'

const ID = 'dsh-machine-control'

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    outDir: 'lib',
    format: 'esm',
    fixedExtension: false,
    platform: 'node',
    target: 'es2024',
    dts: false,
    clean: true,
    deps: { neverBundle: [/^@deepseek-ai\//] },
  },
  {
    entry: { client: 'src/client/index.tsx' },
    outDir: 'lib',
    format: 'cjs',
    platform: 'browser',
    dts: false,
    clean: false,
    deps: { neverBundle: ['react', 'react/jsx-runtime', 'react-dom'] },
    outputOptions: {
      entryFileNames: 'client.js',
      banner: `window.__ModuleLoader__.load({ id: ${JSON.stringify(ID)}, factory: (require) => {`,
      intro: 'var module = { exports: {} }; var exports = module.exports;',
      footer: 'return module.exports; } });',
    },
  },
])
