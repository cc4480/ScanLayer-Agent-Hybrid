import { describe, expect, it } from 'vitest'
import { Config, machineOf } from '../src/deployment.ts'
import { SettingsSchema } from '../src/policy.ts'

// Absolute paths must accept Windows forms as well as POSIX ones: the plugin ships on Windows hosts too.
describe('absolute paths', () => {
  it('accepts drive, UNC, and POSIX state directories', () => {
    for (const stateDir of ['C:\\state\\superagent', 'C:/state/superagent', '\\\\server\\share\\state', '/srv/state']) {
      expect(machineOf(Config({ stateDir })).stateDir).toBe(stateDir)
    }
  })
  it('still rejects relative, home-relative, and drive-relative state directories', () => {
    expect(() => Config({ stateDir: 'relative/dir' })).toThrow()
    expect(() => Config({ stateDir: '~/dir' })).toThrow()
    expect(() => Config({ stateDir: 'C:relative' })).toThrow()
    expect(() => Config({ stateDir: './state' })).toThrow()
  })
  it('accepts a Windows executor directory and still rejects a relative one', () => {
    const parse = (directory: string) => SettingsSchema.parse({ executor: { directory } })
    expect(parse('C:\\work').executor.directory).toBe('C:\\work')
    expect(parse('C:/work').executor.directory).toBe('C:/work')
    expect(parse('/srv/work').executor.directory).toBe('/srv/work')
    expect(parse('').executor.directory).toBe('')
    expect(() => parse('work')).toThrow()
  })
})
