#!/usr/bin/env python3
"""Synthetic tests; every subprocess is mocked and state stays in temp dirs."""
import concurrent.futures
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


if sys.platform.startswith('linux'):
    spec = importlib.util.spec_from_file_location('notify_local', Path(__file__).with_name('notify-local.py'))
    notify_local = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(notify_local)
else:
    notify_local = None


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux desktop host adapter')
class LocalNotifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'state'
        self.history = Path(self.temporary.name) / 'history.ndjson'
        self.unit = 'fixture-worker'
        self.other_unit = 'fixture-other'
        self.notifier = notify_local.LocalNotifier(
            allow_units={self.unit, self.other_unit}, session_user='fixtureuser',
            bus_address='unix:path=/run/user/4242/bus', state_directory=self.root,
            historical_journal=self.history)
        self.server = 'synthetic-bus|:1.15'
        self.status = {self.unit: ('failed', 'run-one'), self.other_unit: ('active', 'run-other')}
        self.monotonic = None
        self.notification_commands = []
        self.all_commands = []
        self.delivery_results = []
        self.transport = mock.patch.object(notify_local.subprocess, 'run', side_effect=self.run_command)
        self.transport.start()
        self.addCleanup(self.transport.stop)

    def run_command(self, command, **kwargs):
        self.all_commands.append(command)
        self.assertNotIn('shell', kwargs)
        self.assertGreater(kwargs['timeout'], 0)
        self.assertEqual(kwargs['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
        self.assertTrue(command[0].startswith('/'))
        if command[0] == '/usr/bin/systemctl':
            self.assertEqual(command[1], 'show')
            active, invocation = self.status[notify_local._unit_stem(command[2])]
            if isinstance(active, Exception):
                raise active
            fields = 'ActiveState=' + active + '\nInvocationID=' + invocation + '\n'
            if self.monotonic is not None:
                fields += ('ExecMainStartTimestampMonotonic=' + self.monotonic[0]
                           + '\nExecMainExitTimestampMonotonic=' + self.monotonic[1] + '\n')
            return subprocess.CompletedProcess(command, 0, fields, '')
        if '/usr/bin/busctl' in command:
            value = self.server.split('|')[0 if 'GetId' in command else 1]
            return subprocess.CompletedProcess(command, 0, 's "' + value + '"\n', '')
        if '/usr/bin/notify-send' in command:
            self.notification_commands.append(command)
            result = self.delivery_results.pop(0) if self.delivery_results else (0, '17\n')
            if isinstance(result, Exception):
                raise result
            return subprocess.CompletedProcess(command, result[0], result[1], 'fixture-private-error')
        self.fail('Unexpected command: ' + str(command))

    def journal(self):
        path = self.root / 'alerts-redacted.ndjson'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def state(self):
        return json.loads((self.root / 'delivery-state.json').read_text())

    def test_same_invocation_event_is_delivered_once(self):
        first = self.notifier.alert(self.unit)
        self.assertTrue(first['desktopDeliveryAccepted'])
        self.assertIsNone(self.notifier.alert(self.unit + '.service'))
        self.assertEqual(len(self.notification_commands), 1)
        self.assertEqual(len(self.journal()), 1)
        self.assertFalse(first['userAcknowledged'])

    def test_new_invocation_and_event_are_independent(self):
        self.notifier.alert(self.unit)
        self.status[self.unit] = ('failed', 'run-two')
        second = self.notifier.alert(self.unit)
        third = self.notifier.alert(self.unit, 'complete')
        self.assertEqual(second['invocationId'], 'run-two')
        self.assertEqual(third['event'], 'complete')
        self.assertEqual(len(self.notification_commands), 3)

    def test_monotonic_fallback_is_bound_to_boot_and_deduplicates_only_within_that_boot(self):
        self.status[self.unit] = ('failed', '')
        self.monotonic = ('1000', '2000')
        first_boot = '11111111-1111-4111-8111-111111111111'
        second_boot = '22222222-2222-4222-8222-222222222222'
        with mock.patch.object(notify_local, '_boot_id', return_value=first_boot):
            first = self.notifier.alert(self.unit)
            self.assertIsNone(self.notifier.alert(self.unit))
        self.notifier = notify_local.LocalNotifier(
            allow_units={self.unit, self.other_unit}, session_user='fixtureuser',
            bus_address='unix:path=/run/user/4242/bus', state_directory=self.root)
        with mock.patch.object(notify_local, '_boot_id', return_value=second_boot):
            second = self.notifier.alert(self.unit)
            self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(first['invocationId'], 'systemd-' + first_boot + '-1000-2000')
        self.assertEqual(second['invocationId'], 'systemd-' + second_boot + '-1000-2000')
        self.assertEqual(len(self.notification_commands), 2)

    def test_monotonic_fallback_without_verified_boot_identity_never_delivers(self):
        self.status[self.unit] = ('failed', '')
        self.monotonic = ('1000', '2000')
        with mock.patch.object(notify_local, '_boot_id', side_effect=OSError('synthetic private metadata')):
            failed = self.notifier.alert(self.unit)
        self.assertFalse(failed['desktopDeliveryAttempted'])
        self.assertEqual(failed['statusQueryError'], 'OSError')
        self.assertEqual(self.notification_commands, [])
        self.assertNotIn('synthetic private metadata', json.dumps(failed))

    def test_boot_identity_reader_accepts_only_bounded_canonical_nonzero_kernel_uuid(self):
        canonical = '11111111-1111-4111-8111-111111111111'
        for raw in (canonical, canonical + '\n'):
            with mock.patch.object(notify_local.os, 'open', return_value=123) as opened, \
                    mock.patch.object(notify_local.os, 'fdopen', return_value=io.StringIO(raw)):
                self.assertEqual(notify_local._boot_id(), canonical)
            self.assertEqual(opened.call_args[0][0], '/proc/sys/kernel/random/boot_id')
            self.assertTrue(opened.call_args[0][1] & os.O_NOFOLLOW)
        invalid = ['', 'not-a-boot-id', '00000000-0000-0000-0000-000000000000',
                   canonical + '\nextra', canonical + ' ', ' ' + canonical]
        for raw in invalid:
            with self.subTest(raw=raw), mock.patch.object(notify_local.os, 'open', return_value=123), \
                    mock.patch.object(notify_local.os, 'fdopen', return_value=io.StringIO(raw)):
                with self.assertRaises(RuntimeError):
                    notify_local._boot_id()

    def test_explicit_and_current_invocation_ids_do_not_depend_on_boot_metadata(self):
        with mock.patch.object(notify_local, '_boot_id', side_effect=AssertionError('unexpected boot probe')):
            self.assertTrue(self.notifier.alert(self.unit)['desktopDeliveryAccepted'])
            self.assertTrue(self.notifier.on_failure(self.unit, '1' * 32)['desktopDeliveryAccepted'])
        self.assertEqual(len(self.notification_commands), 2)

    def test_finite_normal_notification_requests_printed_id(self):
        record = self.notifier.alert(self.unit)
        command = self.notification_commands[0]
        self.assertIn('--print-id', command)
        self.assertEqual(command[command.index('-u') + 1], 'fixtureuser')
        notify_arguments = command[command.index('/usr/bin/notify-send') + 1:]
        self.assertEqual(notify_arguments[notify_arguments.index('-u') + 1], 'normal')
        expiry = int(notify_arguments[notify_arguments.index('-t') + 1])
        self.assertGreater(expiry, 0)
        self.assertLessEqual(expiry, 60000)
        self.assertEqual(record['notificationId'], 17)
        self.assertNotIn('fixture-private-error', json.dumps(record))

    def test_child_commands_exclude_parent_credentials_path_and_bus_overrides(self):
        observed = []

        def inspect(command, **kwargs):
            observed.append((command, kwargs.get('env')))
            return self.run_command(command, **kwargs)

        inherited = {'PATH': '/synthetic/untrusted-bin', 'AARK_SYNTHETIC_SECRET': 'private-value',
                     'LD_PRELOAD': '/synthetic/untrusted.so', 'PYTHONPATH': '/synthetic/private-modules',
                     'DBUS_SESSION_BUS_ADDRESS': 'tcp:host=192.0.2.1,port=12345'}
        with mock.patch.dict(os.environ, inherited), \
                mock.patch.object(notify_local.subprocess, 'run', side_effect=inspect):
            self.assertTrue(self.notifier.alert(self.unit)['desktopDeliveryAccepted'])
        self.assertEqual([command[0] for command, _ in observed], ['/usr/bin/systemctl', '/usr/sbin/runuser'])
        for _, environment in observed:
            self.assertEqual(set(environment), {'PATH', 'LANG', 'LC_ALL'})
            self.assertNotEqual(environment['PATH'], inherited['PATH'])
            self.assertNotIn('private-value', json.dumps(environment))
        delivery = observed[-1][0]
        self.assertIn('/usr/bin/env', delivery)
        self.assertIn('/usr/bin/notify-send', delivery)
        self.assertIn('DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/4242/bus', delivery)
        self.assertNotIn('DBUS_SESSION_BUS_ADDRESS=' + inherited['DBUS_SESSION_BUS_ADDRESS'], delivery)

    def test_malformed_optional_notification_ids_never_erase_accepted_delivery(self):
        invalid = ['²\n', '１２\n', '\ufffd\n', '9' * 5000, '4294967296\n',
                   '0\n', 'synthetic-private-metadata\n']
        for index, output in enumerate(invalid):
            with self.subTest(output=output[:20]):
                self.delivery_results = [(0, output)]
                invocation = 'metadata-' + str(index)
                record = self.notifier.alert(self.unit, invocation_id=invocation)
                self.assertTrue(record['desktopDeliveryAccepted'])
                self.assertNotIn('notificationId', record)
                self.assertEqual(record['notificationIdError'], 'No valid notification ID returned')
                self.assertIsNone(self.notifier.alert(self.unit, invocation_id=invocation))
        self.assertEqual(len(self.notification_commands), len(invalid))
        self.assertNotIn('synthetic-private-metadata', json.dumps(self.state()))
        self.assertNotIn('synthetic-private-metadata', json.dumps(self.journal()))
        self.delivery_results = [(0, '4294967295\n')]
        maximum = self.notifier.alert(self.unit, invocation_id='maximum-id')
        self.assertTrue(maximum['desktopDeliveryAccepted'])
        self.assertEqual(maximum['notificationId'], 0xffffffff)

    def test_delivery_failure_is_durable_and_retries_later(self):
        self.delivery_results = [(1, ''), (0, '23\n')]
        failed = self.notifier.alert(self.unit)
        self.assertFalse(failed['desktopDeliveryAccepted'])
        self.assertIn('deliveryError', self.journal()[0])
        delivered = self.notifier.alert(self.unit)
        self.assertEqual(delivered['attempt'], 2)
        self.assertTrue(delivered['desktopDeliveryAccepted'])
        self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(len(self.notification_commands), 2)

    def test_delivery_timeout_is_recorded_without_controlling_scanner(self):
        self.delivery_results = [subprocess.TimeoutExpired('mock', 15)]
        failed = self.notifier.alert(self.unit)
        self.assertEqual(failed['deliveryError'], 'TimeoutExpired')
        self.assertTrue(self.notifier.alert(self.unit)['desktopDeliveryAccepted'])
        self.assertTrue(all(command[1] == 'show' for command in self.all_commands
                            if command[0] == '/usr/bin/systemctl'))

    def check_restart_does_not_replace_a_reused_notification_id(self, successor):
        legacy = self.notifier.alert(self.unit)
        legacy['notificationServerId'] = self.server
        state = self.state()
        state['deliveries'][legacy['deliveryKey']] = legacy
        state['notifications'][self.unit] = {'id': 17, 'serverId': self.server,
            'acceptedTime': legacy['deliveryAcceptedTime'], 'expireTimeoutMs': 15000}
        (self.root / 'delivery-state.json').write_text(json.dumps(state))
        (self.root / 'alerts-redacted.ndjson').write_text(json.dumps(legacy) + '\n')
        unrelated = {17: 'unrelated notification in successor'}
        self.delivery_results = [(0, '23\n')]

        def restart_during_delivery(command, **kwargs):
            if '/usr/bin/notify-send' in command:
                self.server = successor
                if '--replace-id' in command:
                    unrelated[int(command[command.index('--replace-id') + 1])] = 'replaced'
            return self.run_command(command, **kwargs)

        with mock.patch.object(notify_local.subprocess, 'run', side_effect=restart_during_delivery):
            record = self.notifier.alert(self.unit, invocation_id='run-two')
        self.assertEqual(unrelated[17], 'unrelated notification in successor')
        self.assertTrue(record['desktopDeliveryAccepted'])
        self.assertEqual(record['notificationId'], 23)
        self.assertNotIn('--replace-id', self.notification_commands[-1])
        self.assertNotIn('replacesNotificationId', record)
        self.assertNotIn('notificationServerId', record)
        self.assertNotIn('notificationServerIdentityError', record)
        self.assertFalse(any('/usr/bin/busctl' in command for command in self.all_commands))
        self.assertIsNone(self.notifier.alert(self.unit, invocation_id='run-two'))
        self.assertEqual(len(self.notification_commands), 2)
        return legacy

    def test_daemon_restart_cannot_replace_a_successors_reused_id_or_claim_old_owner(self):
        self.check_restart_does_not_replace_a_reused_notification_id('synthetic-bus|:1.16')

    def test_bus_restart_cannot_replace_reused_id_even_when_unique_owner_is_reused(self):
        self.check_restart_does_not_replace_a_reused_notification_id('successor-bus|:1.15')

    def test_legacy_owner_receipts_remain_deduplicated_after_state_loss(self):
        legacy = self.check_restart_does_not_replace_a_reused_notification_id('synthetic-bus|:1.16')
        (self.root / 'delivery-state.json').unlink()
        self.assertIsNone(self.notifier.alert(self.unit, invocation_id=legacy['invocationId']))
        self.assertEqual(len(self.notification_commands), 2)

    def test_watch_skips_active_units_and_suppresses_repeated_failure(self):
        with contextlib.redirect_stdout(io.StringIO()):
            first = self.notifier.watch()
            second = self.notifier.watch()
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(len(self.notification_commands), 1)

    def test_delayed_failure_handler_uses_old_invocation_without_consuming_next_failure(self):
        old_invocation, next_invocation = '1' * 32, '2' * 32
        self.status[self.unit] = ('active', next_invocation)
        options = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                   '--bus-address', 'unix:path=/run/user/4242/bus', '--on-failure']
        environment = {'MONITOR_UNIT': self.unit + '.service',
                       'MONITOR_INVOCATION_ID': old_invocation,
                       'INVOCATION_ID': '3' * 32}
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(notify_local.main(options), 0)
            self.assertEqual(notify_local.main(options), 0)
        self.assertEqual(self.journal()[0]['invocationId'], old_invocation)
        self.assertFalse(any(command[0] == '/usr/bin/systemctl' for command in self.all_commands))
        self.assertIsNone(self.notifier.alert(self.unit))
        self.status[self.unit] = ('failed', next_invocation)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(len(self.notifier.watch()), 1)
            self.assertEqual(self.notifier.watch(), [])
        self.assertEqual(self.journal()[-1]['invocationId'], next_invocation)
        self.assertEqual(len(self.notification_commands), 2)

    def test_queried_failure_never_consumes_an_active_invocations_later_failure(self):
        self.status[self.unit] = ('active', 'next-run')
        self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(self.notification_commands, [])
        self.status[self.unit] = ('failed', 'next-run')
        self.assertTrue(self.notifier.alert(self.unit)['desktopDeliveryAccepted'])
        self.assertEqual(len(self.notification_commands), 1)

    def test_failure_handler_requires_allowed_monitored_identity_before_delivery(self):
        options = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                   '--bus-address', 'unix:path=/run/user/4242/bus', '--on-failure']
        for environment in ({}, {'INVOCATION_ID': '1' * 32},
                            {'MONITOR_UNIT': self.unit, 'MONITOR_INVOCATION_ID': 'invalid'},
                            {'MONITOR_UNIT': 'unknown.service', 'MONITOR_INVOCATION_ID': '1' * 32},
                            {'MONITOR_UNIT': self.unit, 'MONITOR_INVOCATION_ID': ''}):
            with self.subTest(environment=environment), \
                    mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    notify_local.main(options)
                self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(self.all_commands, [])
        self.assertFalse(self.root.exists())

    def test_service_suffix_is_normalized_once_for_failure_watch_and_replay(self):
        self.notifier = notify_local.LocalNotifier(
            allow_units={'worker.service', 'worker.service.service'}, session_user='fixtureuser',
            bus_address='unix:path=/run/user/4242/bus', state_directory=self.root)
        self.status = {'worker': ('failed', '1' * 32), 'worker.service': ('failed', '2' * 32)}
        first = self.notifier.on_failure('worker.service', '1' * 32)
        second = self.notifier.on_failure('worker.service.service', '2' * 32)
        self.assertEqual(first['unit'], 'worker')
        self.assertEqual(second['unit'], 'worker.service')
        self.assertEqual(second['deliveryKey'], 'worker.service|' + '2' * 32 + '|failed')
        self.assertEqual(self.notification_commands[0][-1], 'worker: inspect the local redacted status.')
        self.assertEqual(self.notification_commands[1][-1], 'worker.service: inspect the local redacted status.')
        (self.root / 'delivery-state.json').unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.notifier.watch(), [])
        queried = [command[2] for command in self.all_commands if command[0] == '/usr/bin/systemctl']
        self.assertEqual(queried, ['worker.service', 'worker.service.service'])
        self.assertEqual(len(self.notification_commands), 2)
        self.assertIsNone(self.notifier.alert('worker.service.service'))
        self.assertIsNone(self.notifier.on_failure('worker.service.service', '2' * 32))
        self.assertEqual(len(self.notification_commands), 2)

    def test_escaped_instance_identity_is_exact_for_failure_direct_watch_and_replay(self):
        external = r'worker@dev-disk-by\x2duuid.service'
        stem = external[:-8]
        self.notifier = notify_local.LocalNotifier(
            allow_units={external}, session_user='fixtureuser',
            bus_address='unix:path=/run/user/4242/bus', state_directory=self.root)
        self.status = {stem: ('failed', '2' * 32)}
        old = self.notifier.on_failure(external, '1' * 32)
        current = self.notifier.alert(external)
        self.assertEqual(old['unit'], stem)
        self.assertEqual(current['unit'], stem)
        self.assertEqual(self.notification_commands[0][-1], stem + ': inspect the local redacted status.')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.notifier.watch(), [])
        (self.root / 'delivery-state.json').unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.notifier.watch(), [])
        self.assertIsNone(self.notifier.on_failure(external, '1' * 32))
        queried = [command[2] for command in self.all_commands if command[0] == '/usr/bin/systemctl']
        self.assertEqual(queried, [external] * 3)
        self.assertEqual(len(self.notification_commands), 2)
        # Hex spelling remains an exact allowlist identity, with no decoding.
        with self.assertRaises(ValueError):
            self.notifier.alert(external.replace('2d', '2D'))

    def test_unit_escapes_reject_arbitrary_backslashes_slashes_and_control_characters(self):
        invalid = [r'worker@bad\stuff.service', r'worker@bad\x2.service',
                   r'worker@bad\xGG.service', r'worker@bad\X2d.service',
                   'worker@bad/name.service', 'worker@bad\nname.service',
                   'worker@bad\rname.service', 'worker@bad\0name.service']
        for unit in invalid:
            with self.subTest(unit=unit):
                with self.assertRaises(ValueError):
                    notify_local.LocalNotifier(allow_units={unit}, session_user='fixtureuser',
                        bus_address='unix:path=/run/user/4242/bus', state_directory=self.root)
        uppercase = notify_local.LocalNotifier(allow_units={r'worker@disk\x2Duuid.service'},
            session_user='fixtureuser', bus_address='unix:path=/run/user/4242/bus', state_directory=self.root)
        self.assertIn(r'worker@disk\x2Duuid', uppercase.allowed)
        self.assertEqual(self.all_commands, [])
        self.assertFalse(self.root.exists())

    def test_watch_retries_rejected_failure_handler_after_unit_restarts_active(self):
        old_invocation, next_invocation = '1' * 32, '2' * 32
        self.status[self.unit] = ('active', next_invocation)
        self.delivery_results = [(1, ''), (0, '23\n')]
        rejected = self.notifier.on_failure(self.unit, old_invocation)
        self.assertFalse(rejected['desktopDeliveryAccepted'])
        # Recovering from the durable journal must preserve the retry as well.
        (self.root / 'delivery-state.json').unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            retried = self.notifier.watch()
            self.assertEqual(self.notifier.watch(), [])
        self.assertEqual(len(retried), 1)
        self.assertEqual(retried[0]['invocationId'], old_invocation)
        self.assertEqual(retried[0]['attempt'], 2)
        self.assertTrue(retried[0]['desktopDeliveryAccepted'])
        self.assertEqual(len(self.notification_commands), 2)

    def test_watch_retries_old_failure_and_delivers_new_failure_without_duplicates(self):
        self.delivery_results = [(1, ''), (0, '23\n'), (0, '24\n')]
        self.assertFalse(self.notifier.alert(self.unit)['desktopDeliveryAccepted'])
        self.status[self.unit] = ('failed', 'next-run')
        with contextlib.redirect_stdout(io.StringIO()):
            delivered = self.notifier.watch()
            self.assertEqual(self.notifier.watch(), [])
        self.assertEqual({row['invocationId'] for row in delivered}, {'run-one', 'next-run'})
        self.assertTrue(all(row['desktopDeliveryAccepted'] for row in delivered))
        self.assertEqual(len(self.notification_commands), 3)

    def test_watch_history_retries_are_bounded_fair_and_skip_current_attempts(self):
        self.delivery_results = [(1, '')] * 12
        for index in range(3):
            self.notifier.on_failure(self.unit, str(index + 1) * 32)
        self.status[self.unit] = ('active', 'next-run')
        retried = []
        with contextlib.redirect_stdout(io.StringIO()):
            for _ in range(3):
                before = len(self.notification_commands)
                records = self.notifier.watch()
                self.assertEqual(len(self.notification_commands) - before, 1)
                self.assertEqual(len(records), 1)
                retried.append(records[0]['invocationId'])
        self.assertEqual(len(set(retried)), 3)
        self.status[self.unit] = ('failed', retried[0])
        with contextlib.redirect_stdout(io.StringIO()):
            records = self.notifier.watch()
        self.assertEqual(len(records), 2)
        self.assertEqual(len({row['deliveryKey'] for row in records}), 2)

    def test_watch_retry_fairness_survives_journal_failure_with_durable_state(self):
        self.delivery_results = [(1, '')] * 8
        self.notifier.alert(self.unit, invocation_id='aaa')
        self.notifier.alert(self.unit, invocation_id='bbb')
        self.status[self.unit] = ('active', 'successor')
        retried = []
        with mock.patch.object(self.notifier, '_append_record', side_effect=OSError('synthetic failure')), \
                contextlib.redirect_stdout(io.StringIO()):
            for _ in range(4):
                records = self.notifier.watch()
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]['journalPersistenceError'], 'OSError')
                self.assertNotIn('statePersistenceError', records[0])
                retried.append((records[0]['invocationId'], records[0]['attempt']))
        self.assertEqual(retried, [('aaa', 2), ('bbb', 2), ('aaa', 3), ('bbb', 3)])
        state = self.state()
        for invocation in ('aaa', 'bbb'):
            key = notify_local._key(self.unit, invocation, 'failed')
            self.assertEqual(state['deliveries'][key]['attempt'], 3)
            self.assertFalse(state['deliveries'][key]['desktopDeliveryAccepted'])
        self.assertEqual([row['attempt'] for row in self.journal()], [1, 1])

    def test_watch_never_retries_unallowed_historical_delivery(self):
        self.delivery_results = [(1, '')]
        self.notifier.alert(self.other_unit, invocation_id='old-unallowed-run')
        self.notifier.allowed.remove(self.other_unit)
        with contextlib.redirect_stdout(io.StringIO()):
            self.notifier.watch()
        self.assertTrue(all(row['unit'] != self.other_unit
                            for row in self.journal()[1:]))
        self.assertEqual(len(self.notification_commands), 2)

    def check_allowlist_change_preserves_cache_only_delivery(self, accepted):
        self.notifier.alert(self.other_unit, invocation_id='removed-unit-run')
        self.delivery_results = [(0, '23\n') if accepted else (1, '')]
        with mock.patch.object(self.notifier, '_append_record', side_effect=OSError('synthetic failure')):
            cached = self.notifier.alert(self.unit, invocation_id='cache-only-run')
        self.assertEqual(cached['desktopDeliveryAccepted'], accepted)
        self.assertIn('journalPersistenceError', cached)
        self.assertNotIn('statePersistenceError', cached)
        self.notifier.allowed.remove(self.other_unit)
        self.status[self.unit] = ('active', 'healthy-successor')
        if accepted:
            self.assertIsNone(self.notifier.alert(self.unit, invocation_id='cache-only-run'))
        with contextlib.redirect_stdout(io.StringIO()):
            retried = self.notifier.watch()
            self.assertEqual(self.notifier.watch(), [])
        if accepted:
            self.assertEqual(retried, [])
        else:
            self.assertEqual(len(retried), 1)
            self.assertEqual(retried[0]['invocationId'], 'cache-only-run')
            self.assertEqual(retried[0]['attempt'], 2)
            self.assertTrue(retried[0]['desktopDeliveryAccepted'])
        self.notifier.allowed.add(self.other_unit)
        self.assertIsNone(self.notifier.alert(self.other_unit, invocation_id='removed-unit-run'))
        self.assertEqual(len(self.notification_commands), 2 if accepted else 3)
        self.assertEqual(len(self.state()['deliveries']), 2)

    def test_narrowed_allowlist_preserves_pending_cache_only_receipt(self):
        self.check_allowlist_change_preserves_cache_only_delivery(False)

    def test_narrowed_allowlist_preserves_accepted_cache_only_receipt(self):
        self.check_allowlist_change_preserves_cache_only_delivery(True)

    def test_status_error_is_recorded_and_later_poll_retries(self):
        self.status[self.unit] = (subprocess.TimeoutExpired('/usr/bin/systemctl', 10), '')
        failed = self.notifier.alert(self.unit, only_if_failed=True)
        self.assertFalse(failed['desktopDeliveryAttempted'])
        self.assertEqual(failed['statusQueryError'], 'TimeoutExpired')
        self.assertIn(self.unit, self.state()['statusErrors'])
        self.assertEqual(self.notification_commands, [])
        self.status[self.unit] = ('failed', 'run-one')
        self.assertTrue(self.notifier.alert(self.unit)['desktopDeliveryAccepted'])

    def test_healthy_status_recovery_clears_error_without_notification(self):
        self.status[self.unit] = (subprocess.TimeoutExpired('/usr/bin/systemctl', 10), '')
        self.notifier.alert(self.unit, only_if_failed=True)
        self.status[self.unit] = ('active', '')
        recovered = self.notifier.alert(self.unit, only_if_failed=True)
        self.assertEqual(recovered['event'], 'status-recovered')
        self.assertTrue(recovered['statusQuerySucceeded'])
        self.assertNotIn(self.unit, self.state()['statusErrors'])
        self.assertIsNone(self.notifier.alert(self.unit, only_if_failed=True))
        self.assertEqual(self.notification_commands, [])

    def test_status_recovery_persists_when_delivery_was_already_accepted(self):
        self.notifier.alert(self.unit)
        self.status[self.unit] = (subprocess.TimeoutExpired('/usr/bin/systemctl', 10), '')
        self.notifier.alert(self.unit)
        self.status[self.unit] = ('failed', 'run-one')
        self.assertIsNone(self.notifier.alert(self.unit))
        self.assertNotIn(self.unit, self.state()['statusErrors'])
        self.assertEqual(len(self.notification_commands), 1)

    def test_historical_seed_suppresses_known_invocation_without_acknowledgement(self):
        rows = [
            {'unit': self.unit, 'event': 'failed', 'desktopDeliveryAccepted': True, 'time': 'synthetic-time'},
            {'unit': self.unit, 'event': 'failed', 'desktopDeliveryAccepted': False},
            {'unit': self.other_unit, 'event': 'failed', 'desktopDeliveryAccepted': True},
        ]
        self.history.write_text('\n'.join(map(json.dumps, rows)) + '\n')
        record = self.notifier.seed_accepted_history(self.unit, 'run-one')
        self.assertTrue(record['seededFromAcceptedHistory'])
        self.assertEqual(record['historicalAcceptedCount'], 1)
        self.assertFalse(record['desktopDeliveryAttempted'])
        self.assertFalse(record['userAcknowledged'])
        self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(self.notification_commands, [])
        self.assertIsNone(self.notifier.seed_accepted_history(self.unit, 'run-one'))

    def test_historical_seed_requires_an_accepted_row_and_configured_path(self):
        self.history.write_text(json.dumps({'unit': self.unit, 'event': 'failed',
                                           'desktopDeliveryAccepted': False}) + '\n')
        with self.assertRaises(ValueError):
            self.notifier.seed_accepted_history(self.unit, 'run-one')
        self.notifier.historical_journal = None
        with self.assertRaises(ValueError):
            self.notifier.seed_accepted_history(self.unit, 'run-one')
        self.assertEqual(self.notification_commands, [])

    def test_historical_seed_normalizes_timestamps_without_copying_arbitrary_values(self):
        invalid_times = [{'diagnostic': 'synthetic-secret-marker'}, 'synthetic-secret-marker',
                         '2030-01-02T03:04:05Z synthetic-secret-marker',
                         '2030-02-31T03:04:05Z', '2030-01-02T03:04:05',
                         '2030-01-02X03:04:05Z', None, 12345]
        for index, value in enumerate(invalid_times):
            with self.subTest(value=value):
                self.history.write_text(json.dumps({'unit': self.unit, 'event': 'failed',
                    'desktopDeliveryAccepted': True, 'time': value}) + '\n')
                output = io.StringIO()
                options = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                           '--bus-address', 'unix:path=/run/user/4242/bus', '--unit', self.unit,
                           '--historical-journal', str(self.history),
                           '--seed-accepted-history', 'seed-' + str(index)]
                with mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                        contextlib.redirect_stdout(output):
                    self.assertEqual(notify_local.main(options), 0)
                self.assertNotIn('historicalLatestTime', json.loads(output.getvalue()))
                self.assertNotIn('synthetic-secret-marker', output.getvalue())
        self.history.write_text(json.dumps({'unit': self.unit, 'event': 'failed',
            'desktopDeliveryAccepted': True, 'time': '2030-01-02T05:04:05.123456+02:00'}) + '\n')
        valid = self.notifier.seed_accepted_history(self.unit, 'valid-seed')
        self.assertEqual(valid['historicalLatestTime'], '2030-01-02T03:04:05.123456+00:00')
        self.assertNotIn('synthetic-secret-marker', json.dumps(self.state()))
        self.assertNotIn('synthetic-secret-marker', json.dumps(self.journal()))
        self.assertEqual(self.notification_commands, [])

    def test_concurrent_poll_and_onfailure_call_deliver_once(self):
        barrier = threading.Barrier(8)
        def invoke(index):
            barrier.wait(timeout=5)
            return self.notifier.alert(self.unit, invocation_id='run-one')
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(invoke, range(8)))
        self.assertEqual(sum(record is not None for record in results), 1)
        self.assertEqual(len(self.notification_commands), 1)
        self.assertEqual(len(self.journal()), 1)

    def test_private_directory_and_durable_files(self):
        self.notifier.alert(self.unit)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        for name in ('delivery.lock', 'delivery-state.json', 'alerts-redacted.ndjson'):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)
        self.assertEqual(len(self.state()['deliveries']), 1)

    def test_journal_recovers_accepted_delivery_after_state_loss_or_corruption(self):
        self.notifier.alert(self.unit)
        (self.root / 'delivery-state.json').write_text('{')
        with (self.root / 'alerts-redacted.ndjson').open('ab') as stream:
            stream.write(b'\xfftruncated')
        self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(len(self.notification_commands), 1)
        (self.root / 'delivery-state.json').unlink()
        self.assertIsNone(self.notifier.alert(self.unit))

    def test_state_write_failure_recovers_from_durable_journal(self):
        with mock.patch.object(self.notifier, '_save_state', side_effect=OSError('private')):
            record = self.notifier.alert(self.unit)
        self.assertTrue(record['desktopDeliveryAccepted'])
        self.assertIn('statePersistenceError', record)
        self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(len(self.notification_commands), 1)

    def test_accepted_receipt_dominates_failed_receipts_in_cache_and_journal(self):
        accepted = self.notifier.alert(self.unit)
        failed = dict(accepted, attempt=10, desktopDeliveryAccepted=False,
                      deliveryError='synthetic rejection')
        path = self.root / 'alerts-redacted.ndjson'
        # A stale failed record cannot replace a known accepted cache entry.
        path.write_text(json.dumps(failed) + '\n')
        self.assertIsNone(self.notifier.alert(self.unit))
        # A journal-only accepted receipt recovers even over a higher failed
        # cache attempt, regardless of the journal's replay order.
        state = self.state()
        state['deliveries'][accepted['deliveryKey']] = failed
        (self.root / 'delivery-state.json').write_text(json.dumps(state))
        for rows in ((accepted, failed), (failed, accepted)):
            path.write_text('\n'.join(map(json.dumps, rows)) + '\n')
            self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(len(self.notification_commands), 1)

    def test_receipt_merge_keeps_newer_attempts_and_is_idempotent_for_equal_attempts(self):
        self.delivery_results = [(1, '')]
        original = self.notifier.alert(self.unit)
        state = self.state()
        key = original['deliveryKey']
        newer = dict(original, attempt=3, deliveryError='newer fixed status')
        self.notifier._remember(state, newer)
        self.notifier._remember(state, original)
        self.notifier._remember(state, dict(newer, deliveryError='equal alternate status'))
        self.assertEqual(state['deliveries'][key], newer)
        self.notifier._remember(state, dict(newer, attempt=4, invocationId='mismatched-key'))
        self.assertEqual(state['deliveries'][key], newer)
        accepted = dict(original, desktopDeliveryAccepted=True)
        self.notifier._remember(state, accepted)
        self.notifier._remember(state, newer)
        self.assertEqual(state['deliveries'][key], accepted)

    def test_torn_journal_tail_cannot_hide_a_new_durable_receipt(self):
        self.root.mkdir(mode=0o700)
        path = self.root / 'alerts-redacted.ndjson'
        for tail in (b'{"torn":', b'{"torn": "\xe2\x82'):
            with self.subTest(tail=tail):
                path.write_bytes(tail)
                self.notification_commands.clear()
                # Model interruption after the journal fsync, before replacing
                # the state file or attempting any recovery writes.
                with mock.patch.object(self.notifier, '_save_state',
                                       side_effect=SystemExit('synthetic interruption')):
                    with self.assertRaises(SystemExit):
                        self.notifier.alert(self.unit)
                self.assertFalse((self.root / 'delivery-state.json').exists())
                rows = path.read_bytes().splitlines()
                self.assertEqual(rows[0], tail)
                self.assertTrue(json.loads(rows[1])['desktopDeliveryAccepted'])
                self.assertIsNone(self.notifier.alert(self.unit))
                self.assertEqual(len(self.notification_commands), 1)

    def test_unterminated_valid_receipt_is_preserved_before_a_new_receipt(self):
        first = self.notifier.alert(self.unit)
        path = self.root / 'alerts-redacted.ndjson'
        first_line = path.read_bytes()[:-1]
        path.write_bytes(first_line)
        (self.root / 'delivery-state.json').unlink()
        self.status[self.unit] = ('failed', 'run-two')
        with mock.patch.object(self.notifier, '_save_state',
                               side_effect=SystemExit('synthetic interruption')):
            with self.assertRaises(SystemExit):
                self.notifier.alert(self.unit)
        contents = path.read_bytes()
        self.assertTrue(contents.startswith(first_line + b'\n'))
        self.assertEqual(len(contents.splitlines()), 2)
        self.assertEqual(json.loads(contents.splitlines()[0]), first)
        self.assertIsNone(self.notifier.alert(self.unit))
        self.status[self.unit] = ('failed', 'run-one')
        self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(len(self.notification_commands), 2)

    def test_terminated_journal_receipts_do_not_gain_empty_lines(self):
        self.notifier.alert(self.unit)
        path = self.root / 'alerts-redacted.ndjson'
        first_line = path.read_bytes()
        self.notifier.alert(self.unit, invocation_id='run-two')
        contents = path.read_bytes()
        self.assertTrue(contents.startswith(first_line))
        self.assertEqual(len(contents.splitlines()), 2)
        self.assertTrue(all(json.loads(line)['desktopDeliveryAccepted']
                            for line in contents.splitlines()))

    def test_journal_write_failure_keeps_accepted_state(self):
        with mock.patch.object(self.notifier, '_append_record', side_effect=OSError('private')):
            record = self.notifier.alert(self.unit)
        self.assertTrue(record['desktopDeliveryAccepted'])
        self.assertIn('journalPersistenceError', record)
        self.assertIsNone(self.notifier.alert(self.unit))
        self.assertEqual(len(self.notification_commands), 1)

    def test_unknown_identifier_is_rejected_before_any_operation(self):
        for unit, event in (('unknown-unit', 'failed'), (self.unit, 'unknown-event')):
            with self.assertRaises(ValueError):
                self.notifier.alert(unit, event)
        self.assertEqual(self.all_commands, [])
        self.assertFalse(self.root.exists())

    def test_configuration_requires_explicit_allowlist_and_local_session(self):
        for options in ({'allow_units': []}, {'allow_units': 'fixture-worker'},
                        {'session_user': '-bad'}, {'bus_address': 'tcp:host=example.invalid'}):
            config = dict(allow_units={self.unit}, session_user='fixtureuser',
                          bus_address='unix:path=/run/user/4242/bus', state_directory=self.root)
            config.update(options)
            with self.assertRaises(ValueError):
                notify_local.LocalNotifier(**config)
        self.assertEqual(self.all_commands, [])
        self.assertFalse(self.root.exists())

    def test_bus_address_accepts_one_local_unix_endpoint_with_strict_escaped_values(self):
        valid = ['unix:path=/run/user/4242/bus',
                 'unix:path=/run/user/4242/bus,guid=' + 'a' * 32,
                 'unix:guid=' + 'B' * 32 + ',path=%2Frun/user/4242/bus',
                 'unix:abstract=/tmp/dbus-synthetic',
                 'unix:abstract=synthetic%20socket,guid=' + '0' * 32]
        for address in valid:
            with self.subTest(address=address):
                adapter = notify_local.LocalNotifier(allow_units={self.unit}, session_user='fixtureuser',
                    bus_address=address, state_directory=self.root)
                self.assertEqual(adapter.bus_address, address)
                self.assertIn('DBUS_SESSION_BUS_ADDRESS=' + address, adapter.user_command)
        self.assertEqual(self.all_commands, [])
        self.assertFalse(self.root.exists())

    def test_bus_address_rejects_transport_alternatives_properties_and_bad_escaping(self):
        invalid = [None, 'tcp:host=192.0.2.1,port=12345',
                   'unix:path=/synthetic/missing;tcp:host=192.0.2.1,port=12345',
                   'unix:path=/first;unix:path=/second', 'unix:path=/first;',
                   'unix:', 'unix:guid=' + 'a' * 32, 'unix:path=', 'unix:abstract=',
                   'unix:path=relative', 'unix:path=/first,path=/second',
                   'unix:path=/first,abstract=second', 'unix:path=/first,fd=3',
                   'unix:fd=3', 'unix:tmpdir=/tmp', 'unix:dir=/tmp',
                   'unix:runtime=yes', 'unix:path=/first,host=remote',
                   'unix:path=/first,guid=not-a-guid',
                   'unix:path=/first,guid=' + 'a' * 32 + ',guid=' + 'b' * 32,
                   'unix:path=/first,', 'unix:path=/bad%', 'unix:path=/bad%2',
                   'unix:path=/bad%GG', 'unix:path=/bad%00', 'unix:path=/bad%0a',
                   'unix:abstract=bad%7f', 'unix:path=/bad\n', 'unix:path=/bad\t',
                   'unix:path=/bad path', 'unix:path=/bad:property', 'unix:path=/bad\\path']
        for address in invalid:
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    notify_local.LocalNotifier(allow_units={self.unit}, session_user='fixtureuser',
                        bus_address=address, state_directory=self.root)
        self.assertEqual(self.all_commands, [])
        self.assertFalse(self.root.exists())

    def test_cli_retries_one_pending_failure_with_original_identity_and_no_current_query(self):
        self.delivery_results = [(1, ''), (0, '23\n')]
        rejected = self.notifier.on_failure(self.unit, '1' * 32)
        self.status[self.unit] = ('active', '2' * 32)
        options = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                   '--bus-address', 'unix:path=/run/user/4242/bus', '--retry-pending-failure']
        output = io.StringIO()
        with mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                contextlib.redirect_stdout(output):
            self.assertEqual(notify_local.main(options), 0)
            self.assertEqual(notify_local.main(options), 0)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['deliveryKey'], rejected['deliveryKey'])
        self.assertEqual(records[0]['invocationId'], '1' * 32)
        self.assertTrue(records[0]['desktopDeliveryAccepted'])
        self.assertFalse(any(command[0] == '/usr/bin/systemctl' for command in self.all_commands))
        self.assertEqual(len(self.notification_commands), 2)

    def test_cli_pending_failure_retry_is_bounded_and_retains_delivery_failure_exit(self):
        self.delivery_results = [(1, '')] * 4
        self.notifier.on_failure(self.unit, '1' * 32)
        self.notifier.on_failure(self.unit, '2' * 32)
        options = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                   '--bus-address', 'unix:path=/run/user/4242/bus', '--retry-pending-failure']
        output = io.StringIO()
        with mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                contextlib.redirect_stdout(output):
            self.assertEqual(notify_local.main(options), 1)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(len(self.notification_commands), 3)

    def test_cli_reports_delivery_and_bookkeeping_failures_to_its_host(self):
        options = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                   '--bus-address', 'unix:path=/run/user/4242/bus', '--unit', self.unit]
        cases = [(None, 0), ({'desktopDeliveryAccepted': True}, 0),
                 ({'desktopDeliveryAttempted': True, 'desktopDeliveryAccepted': False}, 1),
                 ({'statusQueryError': 'TimeoutExpired'}, 1),
                 ({'deliveryInfrastructureError': 'OSError'}, 1),
                 ({'desktopDeliveryAccepted': True, 'statePersistenceError': 'OSError'}, 1),
                 ({'desktopDeliveryAccepted': True, 'journalPersistenceError': 'OSError'}, 1),
                 ({'statusQuerySucceeded': True, 'desktopDeliveryAccepted': False}, 0)]
        for record, expected in cases:
            with self.subTest(record=record), \
                    mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                    mock.patch.object(self.notifier, 'alert', return_value=record), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(notify_local.main(options), expected)
        with mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                mock.patch.object(self.notifier, 'watch', return_value=[{'statusQueryError': 'OSError'}]):
            self.assertEqual(notify_local.main(options[:-2] + ['--watch']), 1)

    def test_cli_forwards_explicit_stable_event_token(self):
        options = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                   '--bus-address', 'unix:path=/run/user/4242/bus', '--unit', self.unit,
                   '--event', 'paused', '--invocation-id', 'case-event-fixture']
        with mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                mock.patch.object(self.notifier, 'alert', return_value=None) as deliver:
            self.assertEqual(notify_local.main(options), 0)
        deliver.assert_called_once_with(self.unit, 'paused', invocation_id='case-event-fixture')
        self.assertEqual(self.all_commands, [])

    def test_cli_stable_event_token_deduplicates_without_systemctl(self):
        options = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                   '--bus-address', 'unix:path=/run/user/4242/bus', '--unit', self.unit,
                   '--invocation-id', 'case-event-fixture']
        with mock.patch.object(notify_local, 'LocalNotifier', return_value=self.notifier), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(notify_local.main(options), 0)
            self.assertEqual(notify_local.main(options), 0)
        self.assertEqual(len(self.notification_commands), 1)
        self.assertFalse(any(command[0] == 'systemctl' for command in self.all_commands))
        self.assertEqual(self.journal()[0]['invocationId'], 'case-event-fixture')

    def test_cli_event_token_cannot_be_combined_with_history_seed_or_watch(self):
        common = ['--allow-unit', self.unit, '--session-user', 'fixtureuser',
                  '--bus-address', 'unix:path=/run/user/4242/bus',
                  '--invocation-id', 'case-event-fixture']
        invalid = [common + ['--unit', self.unit, '--seed-accepted-history', 'fixture-history'],
                   common + ['--watch']]
        for options in invalid:
            with self.subTest(options=options), \
                    mock.patch.object(notify_local, 'LocalNotifier') as constructor, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    notify_local.main(options)
                self.assertEqual(stopped.exception.code, 2)
                constructor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
