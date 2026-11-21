"""Synthetic subprocess tests; never invoke dmsetup or inspect a real mapping."""
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

TABLE = b"0 8 crypt aes-xts-plain64 0123456789abcdef 0 8:1 2048\n"


class DigestTests(unittest.TestCase):
    def run_digest(self, chunks, code=0, ready=True, running=False):
        process = mock.Mock()
        process.stdout.fileno.return_value = 42
        process.wait.return_value = code
        process.poll.return_value = None if running else code
        with mock.patch.object(helper.subprocess, "Popen", return_value=process) as launch, \
                mock.patch.object(helper.select, "select", return_value=([process.stdout], [], []) if ready else ([], [], [])), \
                mock.patch.object(helper.os, "read", side_effect=[*chunks, b""]), \
                mock.patch.object(helper.time, "monotonic", return_value=1):
            value = helper.mapping_digest("253", "0")
        args, options = launch.call_args
        self.assertEqual(args[0], ["/usr/sbin/dmsetup", "table", "--showkeys", "--noflush", "-j", "253", "-m", "0"])
        self.assertIs(options["stderr"], helper.subprocess.DEVNULL)
        self.assertIs(options["stdin"], helper.subprocess.DEVNULL)
        self.assertFalse(options["shell"])
        self.assertEqual(options["cwd"], "/")
        self.assertEqual(set(options["env"]), {"PATH", "LANG", "LC_ALL"})
        return value

    def test_digest_only_includes_literal_key_offset_and_target_changes(self):
        digest = self.run_digest([TABLE[:17], TABLE[17:]])
        self.assertEqual(digest, hashlib.sha256(TABLE).hexdigest())
        for replacement in [TABLE.replace(b"0123456789abcdef", b"fedcba9876543210"), TABLE.replace(b"2048", b"4096"), b"0 8 linear 8:1 2048\n"]:
            self.assertNotEqual(self.run_digest([replacement]), digest)

    def test_key_references_are_bound_as_opaque_references(self):
        referenced = TABLE.replace(b"0123456789abcdef", b":32:logon:synthetic-description")
        self.assertEqual(self.run_digest([referenced]), hashlib.sha256(referenced).hexdigest())
        self.assertNotEqual(self.run_digest([referenced.replace(b"synthetic-description", b"other-description")]), self.run_digest([referenced]))

    def test_malformed_empty_incomplete_and_nonzero_results_never_return_digest(self):
        for data in [b"", b"private-device: " + TABLE, b"bad\n", b"0 0 zero\n", b"1 8 zero\n", TABLE[:-1], TABLE + TABLE,
                     b"0 8 crypt aes key-redacted 0 8:1 2048\n", TABLE.replace(b"0123456789abcdef", b"123"),
                     TABLE.replace(b"0123456789abcdef", b":not-a-kernel-key-reference")]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.run_digest([data])
        with self.assertRaises(ValueError):
            self.run_digest([TABLE], code=1)

    def test_oversized_output_and_deadline_fail_closed(self):
        with self.assertRaises(ValueError):
            self.run_digest([b"x" * (helper.MAX_BYTES + 1)])
        with self.assertRaises(TimeoutError):
            self.run_digest([TABLE], ready=False, running=True)

    def test_invalid_device_numbers_never_spawn(self):
        with mock.patch.object(helper.subprocess, "Popen") as launch:
            for major, minor in [("-1", "0"), ("253", "01"), ("253", "4294967296"), ("--table", "0")]:
                with self.assertRaises(ValueError):
                    helper.mapping_digest(major, minor)
            launch.assert_not_called()

    def test_main_is_silent_on_failures_and_writes_only_a_fixed_digest_on_success(self):
        for result in [ValueError("synthetic private table material"), "not-a-digest", "a" * 64]:
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(helper, "harden"), mock.patch.object(sys, "argv", ["helper", "253", "0"]), \
                    mock.patch.object(helper, "mapping_digest", side_effect=result if isinstance(result, Exception) else None,
                                      return_value=None if isinstance(result, Exception) else result), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = helper.main()
            self.assertEqual(err.getvalue(), "")
            self.assertEqual(out.getvalue(), "a" * 64 + "\n" if result == "a" * 64 else "")
            self.assertEqual(status, 0 if result == "a" * 64 else 1)

    @unittest.skipUnless(sys.platform == "linux", "Linux hardening contract")
    def test_core_dumps_are_disabled_before_native_query(self):
        import resource
        with mock.patch.object(resource, "setrlimit") as limit, mock.patch.object(helper.os, "umask"), \
                mock.patch.object(helper.os, "stat", return_value=type("Stat", (), {"st_mode": 0o100755, "st_nlink": 1, "st_uid": 0})()):
            with self.assertRaises(ValueError):
                helper.harden()
            limit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))


if __name__ == "__main__":
    unittest.main()
