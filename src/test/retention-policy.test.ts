import assert from "node:assert/strict";
import test from "node:test";
import { assertInternalExtJournal, assertRetentionFilesystem, assertRetentionInputMounts } from "../retention.js";
import type { MountRecord } from "../core/mounts.js";

function mounted(target: string, filesystem = "ext4", source = "/dev/synthetic-source"): MountRecord {
  return {source, target, filesystem, options: ["ro"]};
}

test("retention filesystem policy accepts supported ordinary filesystem formats", () => {
  for (const filesystem of ["ext2", "ext3", "ext4", "vfat", "exfat", "ntfs", "ntfs3", "fuse.exfat", "fuse.ntfs", "fuse.ntfs-3g", "fuseblk"]) {
    assert.doesNotThrow(() => assertRetentionFilesystem({filesystem}), filesystem);
  }
});

test("retention rejects source and destination filesystems without supported physical allocation semantics", () => {
  for (const filesystem of ["xfs", "btrfs", "zfs", "bcachefs", "overlay", "tmpfs", "ramfs", "nfs", "nfs4", "cifs", "fuse", "fuse.unknown", "unknown", ""]) {
    // The same policy applies to protected source and destination storage.
    assert.throws(() => assertRetentionFilesystem({filesystem}), /filesystem|supported|physical|storage/i, filesystem);
  }
});

test("retention checks every loop host filesystem rather than only the visible filesystem", () => {
  assert.doesNotThrow(() => assertRetentionFilesystem({filesystem: "ext4"}, [
    {filesystem: "ext3"}, {filesystem: "fuse.exfat"}, {filesystem: "ext4"},
  ]));
  for (const filesystem of ["xfs", "btrfs", "zfs", "bcachefs", "overlay", "tmpfs", "unknown"]) {
    for (const index of [0, 1, 2]) {
      const hosts = [{filesystem: "ext4"}, {filesystem: "ext3"}, {filesystem: "exfat"}];
      hosts[index] = {filesystem};
      assert.throws(() => assertRetentionFilesystem({filesystem: "ext4"}, hosts), /filesystem|supported|physical|storage/i,
        `${filesystem} loop host at layer ${index}`);
    }
  }
});

test("retention input policy accepts its root mount, ancestors, siblings, and individual files", () => {
  const records = [
    mounted("/"),
    mounted("/synthetic"),
    mounted("/synthetic/input"),
    mounted("/synthetic/input-other", "ext3", "/dev/synthetic-neighbor"),
  ];
  assert.doesNotThrow(() => assertRetentionInputMounts("/synthetic/input", "directory", records));
  assert.doesNotThrow(() => assertRetentionInputMounts("/synthetic/input/source.img", "file", [
    ...records, mounted("/synthetic/input/other-volume", "ext4", "/dev/synthetic-other-volume"),
  ]));
});

test("retention refuses any nested input mount including storage without finding sources", () => {
  for (const nested of ["/synthetic/input/ordinary-unmatched", "/synthetic/input/deep/ordinary-unmatched"]) {
    const records = [mounted("/"), mounted("/synthetic/input"), mounted(nested, "ext4", "/dev/synthetic-unmatched-storage")];
    assert.throws(() => assertRetentionInputMounts("/synthetic/input", "directory", records), /nested|mount|input/i);
  }
  // A bind mount onto the same backing source still changes the input topology.
  assert.throws(() => assertRetentionInputMounts("/synthetic/input", "directory", [
    mounted("/synthetic/input"), mounted("/synthetic/input/bind-view"),
  ]), /nested|mount|input/i);
});


test("retention refuses XFS external data and log devices on visible filesystems and loop hosts", () => {
  for (const option of ["rtdev=/dev/synthetic-realtime", "logdev=/dev/synthetic-log"]) {
    assert.throws(() => assertRetentionFilesystem({filesystem: "xfs", options: ["ro", option]}), /filesystem|supported|physical|storage/i);
    assert.throws(() => assertRetentionFilesystem({filesystem: "ext4"}, [{filesystem: "xfs", options: ["ro", option]}]), /filesystem|supported|physical|storage/i);
  }
});

test("retention refuses ext external journal overrides on visible filesystems and every loop host", () => {
  for (const filesystem of ["ext2", "ext3", "ext4"]) {
    assert.doesNotThrow(() => assertRetentionFilesystem({filesystem, options: ["ro", "data=journal"]}));
    for (const option of ["journal_dev=/dev/synthetic-journal", "journal_path=/dev/synthetic-journal"]) {
      assert.throws(() => assertRetentionFilesystem({filesystem, options: ["ro", option]}), /journal|filesystem|supported|physical|storage/i);
      for (const index of [0, 1]) {
        const hosts = [{filesystem: "ext4", options: ["ro"]}, {filesystem: "ext3", options: ["ro"]}];
        hosts[index] = {filesystem, options: ["ro", option]};
        assert.throws(() => assertRetentionFilesystem({filesystem: "ext4"}, hosts), /journal|filesystem|supported|physical|storage/i);
      }
    }
  }
});

function extSuperblock(revision = 1, journal = false): Buffer {
  const value = Buffer.alloc(1024);
  value.writeUInt16LE(0xef53, 0x38);
  value.writeUInt32LE(revision, 0x4c);
  if (journal) { value.writeUInt32LE(0x4, 0x5c); value.writeUInt32LE(8, 0xe0); }
  return value;
}

test("retention ext superblock parser accepts absent and internal journals", () => {
  for (const revision of [0, 1]) assert.equal(assertInternalExtJournal(extSuperblock(revision)), "absent");
  assert.equal(assertInternalExtJournal(extSuperblock(1, true)), "internal");
  const otherFeatures = extSuperblock(1, true);
  otherFeatures.writeUInt32LE(0x24, 0x5c);
  otherFeatures.writeUInt32LE(0x40, 0x60);
  assert.equal(assertInternalExtJournal(otherFeatures), "internal");
});

test("retention ext superblock parser rejects invalid sizes, magic, and revisions", () => {
  for (const length of [0, 1023, 1025, 2048]) assert.throws(() => assertInternalExtJournal(Buffer.alloc(length)), /superblock|size|length|ext|journal/i);
  const wrongMagic = extSuperblock();
  wrongMagic.writeUInt16LE(0, 0x38);
  assert.throws(() => assertInternalExtJournal(wrongMagic), /superblock|magic|ext|journal/i);
  for (const revision of [2, 0xffffffff]) assert.throws(() => assertInternalExtJournal(extSuperblock(revision)), /revision|superblock|ext|journal/i);
});

test("retention ext superblock parser rejects external journals and journal-device filesystems", () => {
  for (const journal of [false, true]) {
    for (let offset = 0xd0; offset < 0xe0; offset++) {
      const uuid = extSuperblock(1, journal);
      uuid[offset] = 1;
      assert.throws(() => assertInternalExtJournal(uuid), /external|journal|uuid|superblock/i);
    }
    const device = extSuperblock(1, journal);
    device.writeUInt32LE(1, 0xe4);
    assert.throws(() => assertInternalExtJournal(device), /external|journal|device|superblock/i);
    const journalDevice = extSuperblock(1, journal);
    journalDevice.writeUInt32LE(0x8, 0x60);
    assert.throws(() => assertInternalExtJournal(journalDevice), /external|journal|device|superblock/i);
  }
});

test("retention ext superblock parser requires a consistent journal feature and inode", () => {
  const missingInode = extSuperblock(1, true);
  missingInode.writeUInt32LE(0, 0xe0);
  assert.throws(() => assertInternalExtJournal(missingInode), /journal|inode|superblock/i);
  assert.throws(() => assertInternalExtJournal(extSuperblock(0, true)), /revision|journal|superblock/i);
  const staleInode = extSuperblock(1);
  staleInode.writeUInt32LE(8, 0xe0);
  assert.throws(() => assertInternalExtJournal(staleInode), /journal|inode|superblock/i);
});
