#!/usr/bin/env node
// Makes the vendored VibeScan workspace packages resolvable by name (@workspace/db, @workspace/api-zod).
// The copied code imports them by package name, as it did in its pnpm workspace. A tsconfig path alias
// only applies when tsx reads this package's tsconfig, which it does not inside the harness process, so
// the packages are linked into node_modules instead. Runs on npm install (postinstall); safe to re-run.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const packages = {
  '@workspace/db': 'src/engines/vibescan-core/lib/db',
  '@workspace/api-zod': 'src/engines/vibescan-core/lib/api-zod',
}

for (const [name, rel] of Object.entries(packages)) {
  const target = path.join(root, rel)
  const link = path.join(root, 'node_modules', ...name.split('/'))
  if (!fs.existsSync(path.join(target, 'package.json'))) throw new Error(`missing ${rel}/package.json`)
  fs.mkdirSync(path.dirname(link), { recursive: true })
  fs.rmSync(link, { recursive: true, force: true })
  // A junction needs no admin rights on Windows; elsewhere it is an ordinary directory symlink.
  fs.symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir')
  console.log(`linked ${name} -> ${rel}`)
}
