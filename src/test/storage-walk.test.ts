import assert from "node:assert/strict";
import fs, { mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { directoryLogicalBytes, StorageQuotaError, assertStorageCapacity, storagePolicyFromGiB } from "../core/storage.js";
import { mkdtemp } from "./helpers.js";

test("quota walks count replayed directory entries once without dropping distinct paths", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-quota-replay-"));
  await mkdir(path.join(root, "evidence"));
  await mkdir(path.join(root, "other"));
  await writeFile(path.join(root, "evidence", "source.img"), Buffer.alloc(800_000));
  await writeFile(path.join(root, "other", "source.img"), Buffer.alloc(400_000));
  await writeFile(path.join(root, "state.json"), "{}");
  const originalOpen = fs.opendir;
  context.mock.method(fs, "opendir", async (...args: Parameters<typeof fs.opendir>) => {
    const directory = await originalOpen(...args);
    const iterate = directory[Symbol.asyncIterator].bind(directory);
    context.mock.method(directory, Symbol.asyncIterator, async function* () {
      // NTFS can replay entries when another process atomically replaces files.
      for await (const entry of iterate()) {
        yield entry;
        yield entry;
      }
    });
    return directory;
  });

  const bytes = await directoryLogicalBytes(root);
  assert.equal(bytes, 1_200_002n);
  const policy = storagePolicyFromGiB(0, 0, 0.002);
  await assertStorageCapacity(root, policy, bytes);
  // A real excess must still trip the configured cap.
  await assert.rejects(assertStorageCapacity(root, policy, 3_000_000n),
    (error: unknown) => error instanceof StorageQuotaError && error.reason === "output-cap");
});

test("quota walks remain cancellable during repeated directory entries", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-quota-abort-"));
  await writeFile(path.join(root, "source.img"), Buffer.alloc(16));
  const controller = new AbortController();
  const originalOpen = fs.opendir;
  context.mock.method(fs, "opendir", async (...args: Parameters<typeof fs.opendir>) => {
    const directory = await originalOpen(...args);
    const iterate = directory[Symbol.asyncIterator].bind(directory);
    context.mock.method(directory, Symbol.asyncIterator, async function* () {
      for await (const entry of iterate()) {
        yield entry;
        controller.abort();
        yield entry;
      }
    });
    return directory;
  });
  await assert.rejects(directoryLogicalBytes(root, controller.signal), /interrupted/);
});
