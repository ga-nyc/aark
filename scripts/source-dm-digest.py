#!/usr/bin/python3
"""Hash a read-only active-table ioctl in one nondumpable process."""
import contextlib
import ctypes
import hashlib
import os
import platform
import re
import stat
import struct
import sys

MAX_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 10
# linux/dm-ioctl.h: struct dm_ioctl and struct dm_target_spec, native endian.
HEADER = struct.Struct("=6Ii3IQ128s129s7s")
TARGET = struct.Struct("=QQiI16s")
TABLE_FLAG = 1 << 4
ACTIVE_FLAG = 1 << 5
BUFFER_FULL_FLAG = 1 << 8
NOFLUSH_FLAG = 1 << 11
INACTIVE_QUERY_FLAG = 1 << 12
SECURE_FLAG = 1 << 15
TABLE_STATUS = (3 << 30) | (HEADER.size << 16) | (0xfd << 8) | 12


def prctl(operation, value=0):
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.prctl
    call.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    call.restype = ctypes.c_int
    return call(operation, value, 0, 0, 0)


def harden():
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64", "armv7l", "riscv64", "i386", "i686"):
        raise ValueError()
    # RLIMIT_CORE alone is ineffective for core_pattern pipe collectors.
    if prctl(4, 0) != 0 or prctl(3) != 0:  # PR_SET_DUMPABLE, PR_GET_DUMPABLE
        raise ValueError()
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)


def silence_native_output():
    output = os.dup(1)
    try:
        null = os.open(os.devnull, os.O_WRONLY | os.O_CLOEXEC)
        try:
            os.dup2(null, 1)
            os.dup2(null, 2)
        finally:
            os.close(null)
        return output
    except BaseException:
        os.close(output)
        raise


@contextlib.contextmanager
def watchdog():
    import signal

    def expired(_number, _frame):
        raise TimeoutError()

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def number(value):
    return re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})", value) is not None and int(value) < 1 << 64


def next_sector(line, expected):
    fields = line.split()
    if len(fields) < 3 or not number(fields[0]) or not number(fields[1]) or int(fields[0]) != expected or int(fields[1]) == 0:
        raise ValueError()
    if re.fullmatch(rb"[a-zA-Z0-9_-]{1,15}", fields[2]) is None or any(byte < 32 and byte != 9 or byte > 126 for byte in line):
        raise ValueError()
    if fields[2] == b"crypt":
        if len(fields) < 8:
            raise ValueError()
        key = fields[4]
        if key.startswith(b":"):
            reference = key.split(b":", 3)
            if len(reference) != 4 or not number(reference[1]) or int(reference[1]) == 0 or re.fullmatch(rb"[a-zA-Z0-9_-]+", reference[2]) is None or not reference[3]:
                raise ValueError()
        elif key != b"-" and re.fullmatch(rb"(?:[a-fA-F0-9]{2})+", key) is None:
            raise ValueError()
    end = expected + int(fields[1])
    if end >= 1 << 64:
        raise ValueError()
    return end


def table_digest(buffer, device):
    if len(buffer) < HEADER.size or len(buffer) > MAX_BYTES:
        raise ValueError()
    fields = HEADER.unpack_from(buffer)
    size, start, count, flags, returned_device = fields[3], fields[4], fields[5], fields[7], fields[10]
    if fields[0] != 4 or not HEADER.size <= start < size <= len(buffer) or start % 8 or not 1 <= count <= 1024 \
            or flags & (BUFFER_FULL_FLAG | INACTIVE_QUERY_FLAG) or not flags & ACTIVE_FLAG or returned_device != device:
        raise ValueError()
    digest = hashlib.sha256()
    offset, sector = start, 0
    for index in range(count):
        if offset + TARGET.size >= size:
            raise ValueError()
        position, length, status, following, target = TARGET.unpack_from(buffer, offset)
        nul = buffer.find(b"\0", offset + TARGET.size, size)
        if status != 0 or nul < 0 or b"\0" not in target:
            raise ValueError()
        kind, padding = target.split(b"\0", 1)
        if any(padding) or following != ((nul + 1 - start + 7) & ~7):
            raise ValueError()
        line = str(position).encode("ascii") + b" " + str(length).encode("ascii") + b" " + kind + b" " + bytes(buffer[offset + TARGET.size:nul])
        sector = next_sector(line, sector)
        digest.update(line + b"\n")
        if index == count - 1:
            if nul + 1 != size:
                raise ValueError()
        else:
            offset = start + following
    return digest.hexdigest()


def mapping_digest(major, minor):
    if any(re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", value) is None for value in (major, minor)) or int(major) > 0xfff or int(minor) > 0xfffff:
        raise ValueError()
    if prctl(3) != 0:  # Verify immediately before fetching any sensitive bytes.
        raise ValueError()
    import fcntl
    device = (int(minor) & 0xff) | (int(major) << 8) | ((int(minor) & ~0xff) << 12)
    buffer = bytearray(MAX_BYTES)
    HEADER.pack_into(buffer, 0, 4, 0, 0, len(buffer), HEADER.size, 0, 0, TABLE_FLAG | NOFLUSH_FLAG | SECURE_FLAG, 0, 0, device, b"", b"", b"")
    descriptor = os.open("/dev/mapper/control", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        control = os.fstat(descriptor)
        if not stat.S_ISCHR(control.st_mode) or control.st_rdev != os.makedev(10, 236) or control.st_uid != 0:
            raise ValueError()
        if fcntl.ioctl(descriptor, TABLE_STATUS, buffer, True) != 0 or prctl(3) != 0:
            raise ValueError()
        return table_digest(buffer, device)
    finally:
        buffer[:] = bytes(len(buffer))
        os.close(descriptor)


def main():
    output = None
    try:
        harden()
        output = silence_native_output()
        if len(sys.argv) != 3:
            raise ValueError()
        with watchdog():
            result = mapping_digest(sys.argv[1], sys.argv[2])
        if re.fullmatch(r"[a-f0-9]{64}", result) is None:
            raise ValueError()
        message = (result + "\n").encode("ascii")
        return 0 if os.write(output, message) == len(message) else 1
    except BaseException:
        return 1
    finally:
        if output is not None:
            os.close(output)


if __name__ == "__main__":
    raise SystemExit(main())
