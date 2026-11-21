import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import { assertNoSymlinkComponents, stableHandleStat, stableLstat } from "../core/fs-safe.js";

export interface CaseLease { assertHeld(): Promise<void>; release(): Promise<void> }

/** The worker retains the flocked open file description. Worker death releases it. */
export async function acquireCaseLease(control: string): Promise<CaseLease> {
  if (process.platform !== "linux") throw new Error("case supervision requires Linux");
  const filename = path.join(control, ".case-service.lock");
  await assertNoSymlinkComponents(control, filename);
  const handle = await open(filename, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
  let released = false;
  try {
    const original = await stableHandleStat(handle);
    if (!original.raw.isFile() || original.raw.nlink !== 1n || (original.raw.mode & 0o077n) !== 0n) throw new Error("invalid case service lock");
    // flock's FD form locks this inherited description without reopening a path.
    await new Promise<void>((resolve, reject) => {
      const child = spawn("/usr/bin/flock", ["--exclusive", "--nonblock", "--conflict-exit-code", "73", "3"],
        {stdio: ["ignore", "ignore", "ignore", handle.fd], env: {PATH: "/usr/bin:/bin", LANG: "C"}});
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("case lease helper unavailable")); }, 5000);
      child.once("error", () => { clearTimeout(timer); reject(new Error("case lease helper unavailable")); });
      child.once("exit", code => { clearTimeout(timer); if (code === 0) resolve(); else reject(new Error("case supervisor already running or lease unavailable")); });
    });
    const lease: CaseLease = {
      assertHeld: async () => {
        if (released) throw new Error("case lease released");
        await assertNoSymlinkComponents(control, filename);
        const current = await stableLstat(filename);
        const opened = await stableHandleStat(handle);
        if (current.device !== original.device || current.inode !== original.inode || current.raw.nlink !== 1n
          || current.raw.isSymbolicLink() || opened.device !== original.device || opened.inode !== original.inode
          || (current.raw.mode & 0o077n) !== 0n) throw new Error("case lease binding changed");
      },
      release: async () => { if (!released) { released = true; await handle.close(); } },
    };
    await lease.assertHeld();
    return lease;
  } catch (error) { await handle.close(); throw error; }
}
