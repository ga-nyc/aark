"""Synthetic ioctl fixtures only; never open a real mapper or fetch real keys."""
import contextlib
import hashlib
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("source_dm_digest", pathlib.Path(__file__).with_name("source-dm-digest.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
DEVICE = 253 << 8
PARAMS = b"aes-xts-plain64 0123456789abcdef 0 8:1 2048"
TABLE = b"0 8 crypt " + PARAMS + b"\n"


def table_buffer(rows=None):
    rows = [(0, 8, b"crypt", PARAMS)] if rows is None else rows
    buffer = bytearray(helper.MAX_BYTES)
    offset, end = helper.HEADER.size, helper.HEADER.size
    for position, length, kind, params in rows:
        end = offset + helper.TARGET.size + len(params) + 1
        following = (end - helper.HEADER.size + 7) & ~7
        helper.TARGET.pack_into(buffer, offset, position, length, 0, following, kind)
        buffer[offset + helper.TARGET.size:end] = params + b"\0"
        offset = helper.HEADER.size + following
    helper.HEADER.pack_into(buffer, 0, 4, 0, 0, end, helper.HEADER.size, len(rows), 0, helper.TABLE_FLAG | helper.ACTIVE_FLAG,
                            0, 0, DEVICE, b"", b"", b"")
    return buffer


class DigestTests(unittest.TestCase):
    def test_header_and_request_match_the_fixed_linux_uapi(self):
        self.assertEqual(helper.HEADER.size, 312)
        self.assertEqual(helper.TARGET.size, 40)
        self.assertEqual(helper.TABLE_STATUS, 0xc138fd0c)
        self.assertFalse(hasattr(helper, "subprocess"), "no exec child may hold table/key bytes")

    def test_digest_binds_literal_key_offset_and_target_changes(self):
        digest = helper.table_digest(table_buffer(), DEVICE)
        self.assertEqual(digest, hashlib.sha256(TABLE).hexdigest())
        for rows in [[(0, 8, b"crypt", PARAMS.replace(b"0123456789abcdef", b"fedcba9876543210"))],
                     [(0, 8, b"crypt", PARAMS.replace(b"2048", b"4096"))], [(0, 8, b"linear", b"8:1 2048")]]:
            self.assertNotEqual(helper.table_digest(table_buffer(rows), DEVICE), digest)

    def test_key_references_remain_opaque_and_kernel_null_keys_are_valid(self):
        referenced = PARAMS.replace(b"0123456789abcdef", b":32:logon:synthetic-description")
        self.assertEqual(helper.table_digest(table_buffer([(0, 8, b"crypt", referenced)]), DEVICE),
                         hashlib.sha256(b"0 8 crypt " + referenced + b"\n").hexdigest())
        null = b"capi:ecb(cipher_null)-plain64 - 0 8:1 2048"
        self.assertEqual(helper.table_digest(table_buffer([(0, 8, b"crypt", null)]), DEVICE), hashlib.sha256(b"0 8 crypt " + null + b"\n").hexdigest())

    def test_multiple_targets_use_offsets_relative_to_the_first_spec(self):
        rows = [(0, 8, b"linear", b"8:1 2048"), (8, 16, b"zero", b"")]
        self.assertEqual(helper.table_digest(table_buffer(rows), DEVICE), hashlib.sha256(b"0 8 linear 8:1 2048\n8 16 zero \n").hexdigest())

    def test_invalid_header_bounds_and_incomplete_tables_fail_closed(self):
        for index, value in [(0, 3), (3, helper.MAX_BYTES + 1), (4, 313), (5, 0), (5, 2), (7, helper.ACTIVE_FLAG | helper.BUFFER_FULL_FLAG),
                             (7, helper.ACTIVE_FLAG | helper.INACTIVE_QUERY_FLAG), (7, 0), (10, DEVICE + 1)]:
            buffer = table_buffer()
            fields = list(helper.HEADER.unpack_from(buffer))
            fields[index] = value
            helper.HEADER.pack_into(buffer, 0, *fields)
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                helper.table_digest(buffer, DEVICE)
        for rows in [[], [(1, 8, b"zero", b"")], [(0, 0, b"zero", b"")], [(0, 8, b"crypt", PARAMS.replace(b"0123456789abcdef", b"123"))]]:
            with self.assertRaises(ValueError):
                helper.table_digest(table_buffer(rows), DEVICE)

    def test_invalid_target_offsets_or_unterminated_parameters_fail_closed(self):
        for mutation in ["next", "status", "type", "params"]:
            buffer = table_buffer()
            values = list(helper.TARGET.unpack_from(buffer, helper.HEADER.size))
            if mutation == "next":
                values[3] += 8
            elif mutation == "status":
                values[2] = 1
            elif mutation == "type":
                values[4] = b"x" * 16
            else:
                buffer[helper.HEADER.unpack_from(buffer)[3] - 1] = 32
            helper.TARGET.pack_into(buffer, helper.HEADER.size, *values)
            with self.assertRaises(ValueError):
                helper.table_digest(buffer, DEVICE)

    def test_main_only_writes_fixed_digest_to_the_saved_descriptor(self):
        for result in [ValueError("synthetic private key bytes"), "not-a-digest", "a" * 64]:
            events = []
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(helper, "harden", side_effect=lambda: events.append("harden")), \
                    mock.patch.object(helper, "silence_native_output", side_effect=lambda: events.append("mute") or 99), \
                    mock.patch.object(helper, "watchdog", return_value=contextlib.nullcontext()), \
                    mock.patch.object(sys, "argv", ["helper", "253", "0"]), \
                    mock.patch.object(helper, "mapping_digest", side_effect=result if isinstance(result, Exception) else None,
                                      return_value=None if isinstance(result, Exception) else result), \
                    mock.patch.object(helper.os, "write", side_effect=lambda _fd, value: len(value)) as write, \
                    mock.patch.object(helper.os, "close"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = helper.main()
            self.assertEqual(events, ["harden", "mute"])
            self.assertEqual(out.getvalue() + err.getvalue(), "")
            self.assertEqual(status, 0 if result == "a" * 64 else 1)
            if status == 0:
                write.assert_called_once_with(99, b"a" * 64 + b"\n")
            else:
                write.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "Linux descriptor flag contract")
    def test_native_stdout_and_stderr_are_redirected_without_releasing_the_digest_descriptor(self):
        with mock.patch.object(helper.os, "dup", return_value=99), mock.patch.object(helper.os, "open", return_value=98), \
                mock.patch.object(helper.os, "dup2") as redirect, mock.patch.object(helper.os, "close") as close:
            self.assertEqual(helper.silence_native_output(), 99)
        self.assertEqual(redirect.call_args_list, [mock.call(98, 1), mock.call(98, 2)])
        close.assert_called_once_with(98)


@unittest.skipUnless(sys.platform == "linux", "Linux process and ioctl contract")
class NativeQueryTests(unittest.TestCase):
    def test_dumpability_is_disabled_and_verified_even_with_a_piped_core_collector(self):
        import resource
        for values, succeeds in [([0, 0], True), ([1], False), ([0, 1], False), ([0, 2], False)]:
            with mock.patch.object(helper, "prctl", side_effect=values) as prctl, mock.patch.object(resource, "setrlimit") as limit, \
                    mock.patch.object(helper.platform, "machine", return_value="x86_64"), mock.patch.object(helper.os, "umask"):
                if succeeds:
                    helper.harden()
                    self.assertEqual(prctl.call_args_list, [mock.call(4, 0), mock.call(3)])
                    limit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))
                else:
                    with self.assertRaises(ValueError):
                        helper.harden()
                    limit.assert_not_called()

    def test_only_read_only_active_secure_noflush_ioctl_can_fetch_the_fixed_buffer(self):
        import fcntl
        captured = []

        def query(descriptor, request, buffer, mutable):
            captured.append(buffer)
            self.assertEqual((descriptor, request, mutable, len(buffer)), (42, helper.TABLE_STATUS, True, helper.MAX_BYTES))
            fields = helper.HEADER.unpack_from(buffer)
            self.assertEqual(fields[7], helper.TABLE_FLAG | helper.NOFLUSH_FLAG | helper.SECURE_FLAG)
            self.assertEqual(fields[10], DEVICE)
            buffer[:] = table_buffer()
            return 0

        with mock.patch.object(helper, "prctl", return_value=0) as prctl, mock.patch.object(helper.os, "open", return_value=42) as opened, \
                mock.patch.object(helper.os, "fstat", return_value=type("Stat", (), {"st_mode": helper.stat.S_IFCHR, "st_rdev": helper.os.makedev(10, 236), "st_uid": 0})()), \
                mock.patch.object(helper.os, "close") as close, mock.patch.object(fcntl, "ioctl", side_effect=query):
            self.assertEqual(helper.mapping_digest("253", "0"), hashlib.sha256(TABLE).hexdigest())
        self.assertEqual(prctl.call_args_list, [mock.call(3), mock.call(3)])
        opened.assert_called_once_with("/dev/mapper/control", helper.os.O_RDONLY | helper.os.O_CLOEXEC | helper.os.O_NOFOLLOW)
        close.assert_called_once_with(42)
        self.assertEqual(set(captured[0]), {0}, "raw ioctl storage is wiped on exit")

    def test_control_identity_and_failed_queries_cannot_escape_buffers(self):
        import fcntl
        captured = []

        def failed_query(_descriptor, _request, buffer, _mutable):
            captured.append(buffer)
            buffer[:] = table_buffer()
            raise OSError("synthetic private kernel-table bytes")

        correct = {"st_mode": helper.stat.S_IFCHR, "st_rdev": helper.os.makedev(10, 236), "st_uid": 0}
        for changes in [{"st_mode": helper.stat.S_IFREG}, {"st_rdev": helper.os.makedev(1, 3)}, {"st_uid": 1000}, {}]:
            with mock.patch.object(helper, "prctl", return_value=0), mock.patch.object(helper.os, "open", return_value=42), \
                    mock.patch.object(helper.os, "fstat", return_value=type("Stat", (), {**correct, **changes})()), \
                    mock.patch.object(helper.os, "close"), mock.patch.object(fcntl, "ioctl", side_effect=failed_query) as query:
                with self.assertRaises(ValueError if changes else OSError):
                    helper.mapping_digest("253", "0")
                if changes:
                    query.assert_not_called()
        self.assertEqual(set(captured[0]), {0})

    def test_invalid_numbers_or_dumpability_never_open_control(self):
        with mock.patch.object(helper.os, "open") as opened, mock.patch.object(helper, "prctl", return_value=1):
            for major, minor in [("-1", "0"), ("253", "01"), ("4096", "0"), ("253", "1048576"), ("253", "0")]:
                with self.assertRaises(ValueError):
                    helper.mapping_digest(major, minor)
            opened.assert_not_called()

    def test_watchdog_always_cancels_its_deadline(self):
        import signal
        with mock.patch.object(signal, "signal") as handler, mock.patch.object(signal, "setitimer") as timer:
            with self.assertRaises(TimeoutError):
                with helper.watchdog():
                    handler.call_args_list[0][0][1](signal.SIGALRM, None)
        self.assertEqual(timer.call_args_list, [mock.call(signal.ITIMER_REAL, helper.TIMEOUT_SECONDS), mock.call(signal.ITIMER_REAL, 0)])


if __name__ == "__main__":
    unittest.main()
