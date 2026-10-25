// Synthetic only. Run after building; use an existing local scratch directory.
// Creates fresh subdirectories and preserves them for local inspection.
import { mkdir, mkdtemp, open, statfs, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { atomicWriteFile, atomicWriteInformationalFile } from '../dist/core/fs-safe.js';

const parent = process.argv[2];
if (!parent || !path.isAbsolute(parent)) throw new Error('provide an absolute local scratch directory');
const capacity = await statfs(parent, { bigint: true });
if (capacity.bavail * capacity.bsize < 256n * 1024n ** 2n) throw new Error('benchmark requires 256 MiB free');
const root = await mkdtemp(path.join(parent, 'aark-progress-benchmark-'));
const payload = Buffer.alloc(32 * 1024, 0x5a);
const probe = await open(path.join(root, 'probe'), 'wx');
const prototype = Object.getPrototypeOf(probe);
const originalSync = prototype.sync;
await probe.close();
let syncCalls = 0;
prototype.sync = async function (...args) {
  syncCalls += 1;
  return await originalSync.apply(this, args);
};
try {
  const variants = [['durable-running', atomicWriteFile], ['atomic-running', atomicWriteInformationalFile]];
  if (process.argv.includes('--reverse')) variants.reverse();
  for (const [mode, publish] of variants) {
    const output = path.join(root, mode);
    await mkdir(output);
    const started = performance.now();
    const syncBefore = syncCalls;
    for (let index = 0; index < 500; index += 1) {
      await writeFile(path.join(output, `ordinary-${index}.txt`), payload, { flag: 'wx' });
      if ((index + 1) % 25 === 0) {
        await publish(path.join(output, 'progress-redacted.json'), JSON.stringify({ status: 'running', files: index + 1 }));
      }
    }
    const liveSyncCalls = syncCalls - syncBefore;
    const liveElapsedMs = performance.now() - started;
    // Both variants retain terminal durability; include that flush in wall time.
    await atomicWriteFile(path.join(output, 'progress-redacted.json'), JSON.stringify({ status: 'complete', files: 500 }));
    process.stdout.write(JSON.stringify({ mode, files: 500, payloadBytes: 500 * payload.length,
      liveSnapshots: 20, liveSyncCalls, terminalSyncCalls: syncCalls - syncBefore - liveSyncCalls,
      liveElapsedMs: Math.round(liveElapsedMs), elapsedIncludingTerminalMs: Math.round(performance.now() - started) }) + '\n');
  }
} finally {
  prototype.sync = originalSync;
}
