import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Duplex, PassThrough } from 'node:stream';
import { candidateValidator, MAX_CANDIDATES, resolveCandidates } from '../src/candidate-resolution.mjs';
import { GET_PROFILE, MAX_PROFILE_BYTES } from '../src/common.mjs';

const alias = 'alice@example.com';
const profile = signature => Buffer.from(JSON.stringify({ profile: { alias }, signature }));
class Swarm extends EventEmitter {
  join() { return { flushed: async () => {} }; }
}
function peer(bytes) {
  return new Duplex({
    read() {},
    write(request, _, callback) {
      assert.deepEqual(request, GET_PROFILE);
      callback();
      queueMicrotask(() => { if (bytes) { this.push(bytes); this.push(null); } });
    },
  });
}

test('a raced structural candidate cannot settle before Rust accepts a later candidate', async () => {
  const swarm = new Swarm(), seen = [];
  let active = 0;
  const lookup = resolveCandidates(swarm, Buffer.alloc(32), alias, async bytes => {
    assert.equal(++active, 1, 'only one IPC candidate may be outstanding');
    seen.push(JSON.parse(bytes).signature);
    await new Promise(resolve => setTimeout(resolve, 5));
    active--;
    return JSON.parse(bytes).signature === 'Rust-accepted';
  });
  swarm.emit('connection', peer(profile('invalid-signature')));
  swarm.emit('connection', peer(profile('Rust-accepted')));
  assert.deepEqual(await lookup, profile('Rust-accepted'));
  assert.deepEqual(seen, ['invalid-signature', 'Rust-accepted']);
});

test('attempt and total candidate bytes are bounded even across rejected peers', async () => {
  const swarm = new Swarm();
  let count = 0;
  const lookup = resolveCandidates(swarm, Buffer.alloc(32), alias, async () => { count++; return false; });
  for (let i = 0; i <= MAX_CANDIDATES; i++) swarm.emit('connection', peer(profile('rejected')));
  await assert.rejects(lookup, /limit exhausted/);
  assert.equal(count, MAX_CANDIDATES);
});

test('malformed and oversized peers are skipped without sending them for validation', async () => {
  const swarm = new Swarm(), seen = [];
  const lookup = resolveCandidates(swarm, Buffer.alloc(32), alias, async bytes => { seen.push(bytes); return true; });
  swarm.emit('connection', peer(Buffer.from('{')));
  swarm.emit('connection', peer(Buffer.alloc(MAX_PROFILE_BYTES + 1)));
  swarm.emit('connection', peer(profile('accepted')));
  assert.deepEqual(await lookup, profile('accepted'));
  assert.equal(seen.length, 1);
});

test('global deadline bounds slow peers and stalled Rust validation', async () => {
  for (const bytes of [null, profile('pending')]) {
    const swarm = new Swarm(), stream = peer(bytes);
    const lookup = resolveCandidates(swarm, Buffer.alloc(32), alias, () => new Promise(() => {}), { timeoutMs: 15 });
    swarm.emit('connection', stream);
    await assert.rejects(lookup, /Discovery timeout/);
    assert.equal(stream.destroyed, true);
    assert.equal(swarm.listenerCount('connection'), 0);
  }
});

test('IPC sends length-prefixed unchanged JSON and requires a bounded explicit reply', async () => {
  const input = new PassThrough(), output = new PassThrough();
  const validate = candidateValidator(input, output), bytes = profile('unverified');
  const rejected = validate(bytes);
  const frame = output.read();
  assert.equal(frame.readUInt32BE(), bytes.length);
  assert.deepEqual(frame.subarray(4), bytes);
  input.write(Buffer.from([0]));
  assert.equal(await rejected, false);
  const accepted = validate(bytes);
  input.write(Buffer.from([1]));
  assert.equal(await accepted, true);
  const invalid = validate(bytes);
  input.write(Buffer.from([1, 1]));
  await assert.rejects(invalid, /Invalid IPC reply/);
  const closed = validate(bytes);
  input.end();
  await assert.rejects(closed, /IPC closed/);
});

test('parent shutdown cancels discovery and destroys pending peer streams promptly', async () => {
  const swarm = new Swarm(), controller = new AbortController(), stream = peer(null);
  const lookup = resolveCandidates(swarm, Buffer.alloc(32), alias, async () => false, { signal: controller.signal });
  swarm.emit('connection', stream);
  controller.abort();
  await assert.rejects(lookup, /Stopped/);
  assert.equal(stream.destroyed, true);
  assert.equal(swarm.listenerCount('connection'), 0);
});
