import assert from 'node:assert/strict';
import test from 'node:test';
import { requireCompatibleDaemon } from '../src/client.mjs';

test('accepts only the v0.5.0 daemon safety protocol', () => {
  assert.doesNotThrow(() => requireCompatibleDaemon({ version: '0.5.0' }));
  assert.throws(
    () => requireCompatibleDaemon({ version: '0.4.0' }),
    (error) => error.code === 'DAEMON_VERSION_MISMATCH' && /Stop the old daemon/.test(error.message),
  );
});
