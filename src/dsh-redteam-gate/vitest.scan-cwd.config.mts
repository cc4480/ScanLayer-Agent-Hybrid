// Runs the scan-core suite with the source repo's api-server folder as the working directory.
// Some copied tests read files by a cwd-relative path ("src/lib/..."), which only resolves there.
import { defineConfig } from 'vitest/config'
import path from 'node:path'
import base from './vitest.scan.config.mts'

const apiServer = path.resolve(__dirname, 'src/engines/vibescan-core/artifacts/api-server')
process.chdir(apiServer)

export default defineConfig({
  ...base,
  root: __dirname,
})
