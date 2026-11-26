import { test } from 'node:test';
import assert from 'node:assert/strict';
import { browserEnv, browserLaunchOptions } from './browserLaunch.js';

const appEnv = {
  PATH: '/usr/bin',
  LANG: 'C.UTF-8',
  DATABASE_URL: 'postgres://user:pw@db/app',
  ENCRYPTION_KEY: 'k'.repeat(44),
  STRIPE_SECRET_KEY: 'sk_live_x',
  RESEND_API_KEY: 're_x',
  ORIGIN_AUTH_SECRET: 'origin',
  DEEPSEEK_API_KEY: 'sk-x',
  HEALTH_DETAIL_TOKEN: 't',
} as NodeJS.ProcessEnv;

test('the browser is started with a short allow-list, never the application\'s secrets', () => {
  const env = browserEnv(appEnv);
  assert.equal(env.PATH, '/usr/bin');
  assert.equal(env.LANG, 'C.UTF-8');
  assert.equal(env.HOME, '/tmp', 'its own writable home, not the app\'s');
  for (const secret of Object.keys(appEnv).filter((k) => !['PATH', 'LANG'].includes(k))) {
    assert.equal(secret in env, false, `${secret} must not reach the browser`);
  }
  assert.equal(JSON.stringify(env).includes('pw@db'), false);
});

test('launch options keep the flags the container needs and use the unprivileged wrapper when one is configured', () => {
  const plain = browserLaunchOptions(appEnv);
  assert.deepEqual(plain.args, ['--no-sandbox', '--disable-dev-shm-usage']);
  assert.equal('executablePath' in plain, false, 'no override outside the image');

  const wrapped = browserLaunchOptions({ ...appEnv, SECLAYER_CHROMIUM_PATH: ' /usr/local/bin/seclayer-chromium ' });
  assert.equal((wrapped as any).executablePath, '/usr/local/bin/seclayer-chromium');
  assert.equal(JSON.stringify(wrapped).includes('ENCRYPTION_KEY'), false);
});
