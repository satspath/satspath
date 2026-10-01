import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

test('bridge fails closed on invalid local IPC and exposes no input in logs', { timeout: 30_000 }, async () => {
  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/bridge.mjs', import.meta.url)), 'publish', 'alice@example.com']);
  let output = '';
  child.stdout.on('data', bytes => { output += bytes; });
  child.stderr.on('data', bytes => { output += bytes; });
  const exited = once(child, 'exit');
  child.stdin.end('{private_secret:do-not-log}\n');
  try {
    const [code] = await exited;
    assert.equal(code, 1);
    assert.equal(output, '');
  } finally { child.kill(); }
});
