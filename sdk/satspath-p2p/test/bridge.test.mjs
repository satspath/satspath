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

test('failed announcement never acknowledges an active publisher', { timeout: 10_000 }, async () => {
  const bridge = new URL('../src/bridge.mjs', import.meta.url);
  // Exercise the real discovery.flushed() behavior: failed queries resolve false
  // rather than throwing. No peer profile is announced by this fault injection.
  const script = `
    import { createRequire } from 'node:module';
    import Hyperswarm from 'hyperswarm';
    // Keep this subprocess's DHT completely isolated from public bootstrap nodes.
    createRequire(import.meta.url)('hyperdht/lib/constants').BOOTSTRAP_NODES.length = 0;
    const join = Hyperswarm.prototype.join;
    let announcementCalled = false;
    Hyperswarm.prototype.join = function (...args) {
      this.listen = async () => {};
      this.dht.announce = () => {
        announcementCalled = true;
        throw new Error('Injected announcement failure');
      };
      return join.apply(this, args);
    };
    process.argv = [process.execPath, ${JSON.stringify(fileURLToPath(bridge))}, 'publish', 'alice@example.test'];
    await import(${JSON.stringify(bridge.href)});
    // Any earlier failure must not satisfy the expected exit code of 1.
    if (!announcementCalled) process.exitCode = 2;
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
  });
  let output = '';
  child.stdout.on('data', bytes => { output += bytes; });
  child.stderr.on('data', bytes => { output += bytes; });
  child.stdin.on('error', () => {});
  const exited = once(child, 'exit', { signal: AbortSignal.timeout(5000) });
  child.stdin.write(JSON.stringify({ profile: { alias: 'alice@example.test' }, signature: 'fixture' }) + '\n');
  try {
    const [code] = await exited;
    assert.equal(code, 1);
    assert.equal(output, '');
  } finally { child.kill('SIGKILL'); }
});
