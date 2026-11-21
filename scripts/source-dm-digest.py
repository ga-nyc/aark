#!/usr/bin/python3
"""Hash an active mapping privately; only a fixed digest may leave this process."""
import hashlib
import os
import re
import select
import stat
import subprocess
import sys
import time

MAX_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 10
DMSETUP = "/usr/sbin/dmsetup"


def harden():
    if sys.platform != "linux":
        raise ValueError()
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    canonical = os.path.realpath(DMSETUP)
    metadata = os.stat(canonical)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError()
    directory = os.path.dirname(canonical)
    while True:
        metadata = os.stat(directory)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError()
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent


def number(value):
    return re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})", value) is not None and int(value) < 1 << 64


def next_sector(line, expected):
    fields = line.split()
    if len(fields) < 3 or not number(fields[0]) or not number(fields[1]) or int(fields[0]) != expected or int(fields[1]) == 0:
        raise ValueError()
    if re.fullmatch(rb"[a-zA-Z0-9_-]{1,32}", fields[2]) is None or any(byte < 32 and byte != 9 or byte > 126 for byte in line):
        raise ValueError()
    if fields[2] == b"crypt":
        if len(fields) < 8:
            raise ValueError()
        key = fields[4]
        if key.startswith(b":"):
            reference = key.split(b":", 3)
            if len(reference) != 4 or not number(reference[1]) or int(reference[1]) == 0 or re.fullmatch(rb"[a-zA-Z0-9_-]+", reference[2]) is None or not reference[3]:
                raise ValueError()
        elif re.fullmatch(rb"(?:[a-fA-F0-9]{2})+", key) is None:
            raise ValueError()
    end = expected + int(fields[1])
    if end >= 1 << 64:
        raise ValueError()
    return end


def mapping_digest(major, minor):
    if any(re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", value) is None or int(value) > 0xffffffff for value in (major, minor)):
        raise ValueError()
    deadline = time.monotonic() + TIMEOUT_SECONDS
    process = subprocess.Popen([DMSETUP, "table", "--showkeys", "--noflush", "-j", major, "-m", minor],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               shell=False, close_fds=True, cwd="/",
                               env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
    digest = hashlib.sha256()
    consumed = 0
    pending = b""
    sector = 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise TimeoutError()
            chunk = os.read(process.stdout.fileno(), min(32768, MAX_BYTES - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > MAX_BYTES:
                raise ValueError()
            digest.update(chunk)
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                sector = next_sector(line, sector)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0 or consumed == 0 or pending or sector == 0:
            raise ValueError()
        return digest.hexdigest()
    finally:
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        process.stdout.close()


def main():
    try:
        harden()
        if len(sys.argv) != 3:
            raise ValueError()
        result = mapping_digest(sys.argv[1], sys.argv[2])
        if re.fullmatch(r"[a-f0-9]{64}", result) is None:
            raise ValueError()
        sys.stdout.write(result + "\n")
        return 0
    except BaseException:
        # Never serialize an exception, command output, table, or key material.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
