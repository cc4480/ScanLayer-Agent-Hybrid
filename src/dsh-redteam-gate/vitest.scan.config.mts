// Test config for the verbatim VibeScan scan core. Aliases mirror the source repo's tsconfig paths
// so the copied code resolves its workspace imports exactly as it did in the source repo.
import { defineConfig } from 'vitest/config'
import path from 'node:path'

const here = (p: string) => path.resolve(__dirname, p)

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@workspace\/db$/, replacement: here('src/engines/vibescan-core/lib/db/src/index.ts') },
      { find: /^@workspace\/api-zod$/, replacement: here('src/engines/vibescan-core/lib/api-zod/src/index.ts') },
      { find: /^@\/(.*)$/, replacement: here('src/engines/vibescan-core/artifacts/api-server/src/$1') },
    ],
  },
  test: {
    include: ['src/engines/vibescan-core/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30000,
  },
})
