import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertLoopBackingCapacity, assertSupportedLoopOutputBackings, loopStatusFromJson, resolveBlockBackingFrom, stableLoopBackingIdentity,
  type BlockBackingProbe, type LoopBackingIdentity, type LsblkTransportNode } from "../core/mounts.js";
import { StorageQuotaError } from "../core/storage.js";

function disk(device = "/dev/external"): LsblkTransportNode {
  return { path: device, type: "disk", tran: "usb", subsystems: "block:scsi:usb" };
}

function loopIdentity(device = "/dev/loop7"): LoopBackingIdentity {
  return { device, backingFile: "/external/workspace.img", fileDevice: "2050", fileInode: "12345", bytes: "1048576",
    modifiedNs: "100", changedNs: "100", offset: "0", sizeLimit: "0",
    mount: JSON.stringify({ source: "/dev/external1", target: "/external", filesystem: "ext4", options: ["rw"] }) };
}

function fixture(): { probe: BlockBackingProbe; graphs: Map<string, LsblkTransportNode[]>; bindings: Map<string, Awaited<ReturnType<BlockBackingProbe["loop"]>>> } {
  const graphs = new Map<string, LsblkTransportNode[]>([
    ["/dev/loop7", [{ path: "/dev/loop7", type: "loop" }]],
    ["/dev/external1", [{ path: "/dev/external1", type: "part", children: [disk()] }]],
    ["/dev/internal1", [{ path: "/dev/internal1", type: "part", children: [disk("/dev/internal")] }]],
  ]);
  const bindings = new Map([["/dev/loop7", { identity: loopIdentity(), mountSource: "/dev/external1", networkBacked: false }]]);
  return { graphs, bindings, probe: {
    topology: async (device) => structuredClone(graphs.get(device) ?? []),
    loop: async (device) => {
      const value = bindings.get(device);
      if (value === undefined) throw new Error("missing synthetic loop binding");
      return structuredClone(value);
    },
  } };
}

test("physical resolution follows loops to host disks and preserves same-source comparisons", async () => {
  const { probe } = fixture();
  const direct = await resolveBlockBackingFrom("/dev/external1", probe);
  assert.deepEqual(direct, { devices: ["/dev/external"], networkBacked: false, loopBackings: [] });
  const loop = await resolveBlockBackingFrom("/dev/loop7", probe);
  assert.deepEqual(loop.devices, direct.devices);
  assert.equal(loop.loopBackings.length, 1);
  const internal = await resolveBlockBackingFrom("/dev/internal1", probe);
  assert.equal(internal.devices.some((device) => loop.devices.includes(device)), false);
  // Moving the container to the source disk must make the devices intersect.
  const local = fixture();
  local.bindings.get("/dev/loop7")!.mountSource = "/dev/internal1";
  const same = await resolveBlockBackingFrom("/dev/loop7", local.probe);
  assert.equal(internal.devices.some((device) => same.devices.includes(device)), true);
});

test("nested loops behind device-mapper resolve every parent and deduplicate disks", async () => {
  const { probe, graphs, bindings } = fixture();
  graphs.set("/dev/mapper/work", [{ path: "/dev/mapper/work", type: "crypt", children: [
    { path: "/dev/loop7", type: "loop" }, disk(),
  ] }]);
  graphs.set("/dev/loop8", [{ path: "/dev/loop8", type: "loop" }]);
  bindings.get("/dev/loop7")!.mountSource = "/dev/loop8";
  bindings.set("/dev/loop8", { identity: { ...loopIdentity("/dev/loop8"), fileInode: "54321" },
    mountSource: "/dev/external1", networkBacked: false });
  const result = await resolveBlockBackingFrom("/dev/mapper/work", probe);
  assert.deepEqual(result.devices, ["/dev/external"]);
  assert.deepEqual(result.loopBackings.map((item) => item.device), ["/dev/loop7", "/dev/loop8"]);
});

test("unknown topology branches and non-block loop hosts cannot be treated as local disks", async () => {
  const { probe, graphs, bindings } = fixture();
  graphs.set("/dev/mixed", [{ path: "/dev/mixed", type: "dm", children: [disk(), { path: "/dev/opaque", type: "unknown" }] }]);
  await assert.rejects(resolveBlockBackingFrom("/dev/mixed", probe), /every physical device/);
  bindings.get("/dev/loop7")!.mountSource = "overlay";
  await assert.rejects(resolveBlockBackingFrom("/dev/loop7", probe), /verifiable block filesystem/);
  graphs.set("/dev/loop7", []);
  await assert.rejects(resolveBlockBackingFrom("/dev/loop7", probe), /requested device/);
});

test("repeated device-mapper roots retain all physical parent branches", async () => {
  const { probe, graphs } = fixture();
  graphs.set("/dev/dm-0", [
    { path: "/dev/dm-0", type: "lvm", children: [disk("/dev/one")] },
    { path: "/dev/dm-0", type: "lvm", children: [disk("/dev/two")] },
  ]);
  assert.deepEqual((await resolveBlockBackingFrom("/dev/dm-0", probe)).devices, ["/dev/one", "/dev/two"]);
  graphs.get("/dev/dm-0")!.push({ path: "/dev/unrelated", type: "disk" });
  await assert.rejects(resolveBlockBackingFrom("/dev/dm-0", probe), /requested device/);
});

test("network filesystems and remote block transports remain rejected behind loop layers", async () => {
  const { probe, graphs, bindings } = fixture();
  bindings.get("/dev/loop7")!.networkBacked = true;
  bindings.get("/dev/loop7")!.mountSource = "server:/remote";
  assert.equal((await resolveBlockBackingFrom("/dev/loop7", probe)).networkBacked, true);
  bindings.get("/dev/loop7")!.networkBacked = false;
  bindings.get("/dev/loop7")!.mountSource = "/dev/external1";
  for (const node of [disk("/dev/nbd0"), { ...disk(), tran: "iscsi" },
    { ...disk(), tran: "nvme", subsystems: "block:nvme:nvme-fabrics" }]) {
    graphs.set("/dev/external1", [{ path: "/dev/external1", type: "part", children: [node] }]);
    assert.equal((await resolveBlockBackingFrom("/dev/loop7", probe)).networkBacked, true);
  }
});

test("loop cycles and excessive graph depth stop within bounded work", async () => {
  const { probe, graphs, bindings } = fixture();
  bindings.get("/dev/loop7")!.mountSource = "/dev/loop7";
  await assert.rejects(resolveBlockBackingFrom("/dev/loop7", probe), /cyclic/);
  let root = disk();
  for (let index = 0; index < 20; index += 1) root = { path: `/dev/layer${index}`, type: "dm", children: [root] };
  graphs.set("/dev/layer19", [root]);
  await assert.rejects(resolveBlockBackingFrom("/dev/layer19", probe), /bounded safety limit/);
});

test("replacement, resized, re-offset, and remounted loop bindings invalidate resolution", async () => {
  const replacements: Partial<LoopBackingIdentity>[] = [
    { fileInode: "777" }, { fileDevice: "777" }, { bytes: "2097152" }, { offset: "512" },
    { sizeLimit: "512" }, { backingFile: "/replacement/file" }, { mount: "different-host-mount" },
  ];
  for (const replacement of replacements) {
    const { probe } = fixture();
    const original = probe.loop;
    let calls = 0;
    probe.loop = async (device) => {
      const binding = await original(device);
      if (calls++ > 0) Object.assign(binding.identity, replacement);
      return binding;
    };
    await assert.rejects(resolveBlockBackingFrom("/dev/loop7", probe), /identity changed/);
  }
});

test("ordinary writes may change backing timestamps without changing its fixed binding", async () => {
  const { probe } = fixture();
  const original = probe.loop;
  let calls = 0;
  probe.loop = async (device) => {
    const binding = await original(device);
    binding.identity.modifiedNs = String(++calls);
    binding.identity.changedNs = String(calls);
    return binding;
  };
  assert.equal((await resolveBlockBackingFrom("/dev/loop7", probe)).loopBackings.length, 1);
  const first = loopIdentity();
  assert.equal(stableLoopBackingIdentity([first]), stableLoopBackingIdentity([{ ...first, modifiedNs: "999", changedNs: "999" }]));
  assert.notEqual(stableLoopBackingIdentity([first]), stableLoopBackingIdentity([{ ...first, fileInode: "999" }]));
});

test("loop JSON identities reject wrong devices, deleted paths, and lossy numeric identities", () => {
  const row = { name: "/dev/loop7", "back-file": "/external/workspace.img", "back-ino": "9007199254740993",
    "back-maj:min": "8:2", offset: 0, sizelimit: 0 };
  const parse = (value: Record<string, unknown>) => loopStatusFromJson(JSON.stringify({ loopdevices: [value] }), "/dev/loop7");
  assert.equal(parse(row).inode, "9007199254740993");
  for (const replacement of [{ name: "/dev/loop8" }, { "back-file": "/external/file (deleted)" },
    { "back-file": "relative/file" }, { "back-file": "/external/../file" }, { "back-file": "/external/file\0" },
    { "back-ino": Number.MAX_SAFE_INTEGER + 1 }, { offset: -1 }, { sizelimit: 0.5 }, { "back-maj:min": "unknown" }]) {
    assert.throws(() => parse({ ...row, ...replacement }));
  }
  assert.throws(() => loopStatusFromJson('{"loopdevices":[]}', "/dev/loop7"));
});

test("the host filesystem reserve is enforced independently of the case's logical cap", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "aark-loop-reserve-"));
  try {
    const file = path.join(directory, "synthetic-container");
    await writeFile(file, "synthetic");
    const backing = { ...loopIdentity(), backingFile: file };
    await assertLoopBackingCapacity([backing], { minimumFreeBytes: 0n, minimumFreePercent: 0, maximumOutputBytes: 1n });
    await assert.rejects(assertLoopBackingCapacity([backing], { minimumFreeBytes: 1n << 100n, minimumFreePercent: 0 }), StorageQuotaError);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an ext4 workspace cannot hide an unsupported NTFS3 output host", () => {
  const backing = loopIdentity();
  assert.doesNotThrow(() => assertSupportedLoopOutputBackings([backing]));
  backing.mount = JSON.stringify({ filesystem: "ntfs3" });
  assert.throws(() => assertSupportedLoopOutputBackings([backing]), /ntfs3 output mounts/);
});
