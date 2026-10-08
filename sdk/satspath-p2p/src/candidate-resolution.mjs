import { GET_PROFILE, MAX_PROFILE_BYTES, parseProfile, readBounded } from './common.mjs';

export const MAX_CANDIDATES = 16;
export const DISCOVERY_TIMEOUT_MS = 25_000;

// Private IPC only: u32 big-endian length + unchanged profile JSON, then one
// Rust reply byte (0 = reject, 1 = accept). One candidate is outstanding at a time.
export function candidateValidator(input, output) {
  return bytes => new Promise((resolve, reject) => {
    function cleanup() {
      input.off('data', reply); input.off('end', closed); input.off('close', closed); input.off('error', fail);
    }
    function fail(error) { cleanup(); reject(error); }
    function closed() { fail(new Error('IPC closed')); }
    function reply(chunk) {
      cleanup();
      if (chunk.length !== 1 || chunk[0] > 1) reject(new Error('Invalid IPC reply'));
      else resolve(chunk[0] === 1);
    }
    input.on('data', reply); input.once('end', closed); input.once('close', closed); input.once('error', fail);
    const frame = Buffer.alloc(4 + bytes.length);
    frame.writeUInt32BE(bytes.length); bytes.copy(frame, 4);
    output.write(frame, error => { if (error) fail(error); });
  });
}

// Structural parsing never settles discovery. Only the Rust validator can accept.
export function resolveCandidates(swarm, topic, alias, validate, {
  timeoutMs = DISCOVERY_TIMEOUT_MS,
  peerTimeoutMs = 10_000,
  signal,
} = {}) {
  return new Promise((resolve, reject) => {
    let settled = false, attempts = 0, pending = 0;
    let queue = Promise.resolve();
    const streams = new Set();
    const timer = setTimeout(() => finish(new Error('Discovery timeout')), timeoutMs);
    function finish(error, bytes) {
      if (settled) return;
      settled = true; clearTimeout(timer);
      swarm.off('connection', connection); swarm.off('error', failed);
      signal?.removeEventListener('abort', aborted);
      for (const stream of streams) stream.destroy();
      if (error) reject(error); else resolve(bytes);
    }
    function failed() { finish(new Error('Swarm error')); }
    function aborted() { finish(new Error('Stopped')); }
    function connection(stream) {
      stream.on('error', () => {});
      if (settled || attempts >= MAX_CANDIDATES) { stream.destroy(); return; }
      attempts++; pending++; streams.add(stream);
      (async () => {
        try {
          const response = readBounded(stream, MAX_PROFILE_BYTES, peerTimeoutMs);
          stream.end(GET_PROFILE);
          const bytes = await response;
          parseProfile(bytes, alias);
          const validation = queue.then(async () => {
            if (settled) return;
            if (await validate(bytes)) finish(null, bytes);
          });
          // IPC failure is fatal; a Rust rejection is not.
          queue = validation.catch(error => finish(error));
          await queue;
        } catch { /* Malformed, oversized or timed-out peer: try another. */ }
        finally {
          streams.delete(stream); stream.destroy(); pending--;
          if (!settled && attempts >= MAX_CANDIDATES && pending === 0) {
            finish(new Error('Candidate limit exhausted'));
          }
        }
      })();
    }
    swarm.on('error', failed); swarm.on('connection', connection);
    signal?.addEventListener('abort', aborted, { once: true });
    if (signal?.aborted) { aborted(); return; }
    try {
      const discovery = swarm.join(topic, { server: false, client: true });
      Promise.resolve(discovery.flushed()).catch(failed);
    } catch { failed(); }
  });
}
