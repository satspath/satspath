// Private local IPC entry point. stdin/stdout carry public objects only.
import Hyperswarm from 'hyperswarm';
import { MAX_PROFILE_BYTES, parseProfile, serveProfile, topicForAlias } from './common.mjs';
import { candidateValidator, resolveCandidates } from './candidate-resolution.mjs';

const [mode, alias, ...extra] = process.argv.slice(2);
let swarm;
let cancelled = false;
let finish;
let refill;
let shutdownPromise;
let resolutionController;
const stopped = new Promise(resolve => { finish = resolve; });
const stop = () => {
  cancelled = true;
  resolutionController?.abort();
  finish();
  shutdownPromise ??= (swarm ? swarm.destroy() : Promise.resolve()).catch(() => { process.exitCode = 1; });
  return shutdownPromise;
};
process.once('SIGINT', stop);
process.once('SIGTERM', stop);
try {
  if (extra.length || !['publish', 'resolve'].includes(mode)) throw new Error('Invalid mode');
  const topic = topicForAlias(alias);
  // Status never contains identifiers, endpoints, profiles, or keys.
  if (mode === 'publish') {
    // A single newline-delimited public snapshot; no paths or configuration.
    const bytes = await new Promise((resolve, reject) => {
      let chunks = [];
      let size = 0;
      const timer = setTimeout(() => reject(new Error('IPC timeout')), 10_000);
      const data = chunk => {
        size += chunk.length;
        if (size > MAX_PROFILE_BYTES + 1) { clearTimeout(timer); reject(new Error('IPC limit')); return; }
        chunks.push(chunk);
        if (chunk.includes(10)) {
          clearTimeout(timer);
          process.stdin.off('data', data);
          const all = Buffer.concat(chunks);
          if (all[all.length - 1] !== 10 || all.subarray(0, -1).includes(10)) reject(new Error('Invalid frame'));
          else resolve(all.subarray(0, -1));
        }
      };
      process.stdin.on('data', data);
      process.stdin.once('end', () => { clearTimeout(timer); reject(new Error('IPC closed')); });
    });
    const profile = parseProfile(bytes, alias);
    if (cancelled) throw new Error('Stopped');
    swarm = new Hyperswarm({ maxPeers: 16 });
    swarm.on('error', stop);
    let tokens = 32;
    refill = setInterval(() => { tokens = 32; }, 10_000);
    swarm.on('connection', stream => {
      if (profile.profile.revoked || (profile.profile.expires_at != null && profile.profile.expires_at <= Math.floor(Date.now() / 1000))) {
        stream.on('error', () => {}); stream.destroy(); return;
      }
      if (tokens-- <= 0) { stream.on('error', () => {}); stream.destroy(); return; }
      serveProfile(stream, bytes, () => {}, () => {}, () =>
        !profile.profile.revoked && (profile.profile.expires_at == null || profile.profile.expires_at > Math.floor(Date.now() / 1000)));
    });
    process.stdin.once('end', stop);
    process.stdin.on('data', stop); // No repeated local commands in this version.
    const announced = await swarm.join(topic, { server: true, client: false }).flushed();
    if (!announced) throw new Error('Announcement failed');
    if (!cancelled) process.stdout.write('active\n');
    await stopped;
  } else {
    swarm = new Hyperswarm({ maxPeers: 16 });
    // Parent death closes the IPC pipe, so even a resolving child exits promptly.
    process.stdin.once('end', stop);
    process.stdin.resume();
    resolutionController = new AbortController();
    const lookup = resolveCandidates(swarm, topic, alias, candidateValidator(process.stdin, process.stdout), { signal: resolutionController.signal });
    await Promise.race([lookup, stopped.then(() => { throw new Error('Stopped'); })]);
  }
} catch {
  process.exitCode = 1;
} finally {
  clearInterval(refill);
  await stop();
  process.stdin.destroy();
}
