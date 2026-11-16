#!/usr/bin/env python3
"""Synthetic tests; every subprocess is mocked and state stays in temp dirs."""
import concurrent.futures
import contextlib
import datetime
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
        if command[0] == 'systemctl':
            self.assertEqual(command[1], 'show')
            active, invocation = self.status[command[2].removesuffix('.service')]
            if isinstance(active, Exception):
                raise active
            return subprocess.CompletedProcess(command, 0,
                'ActiveState=' + active + '\nInvocationID=' + invocation + '\n', '')
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
                            if command[0] == 'systemctl'))

    def test_live_notification_id_replaced_only_on_same_bus_and_server(self):
        self.notifier.alert(self.unit)
        record = self.notifier.alert(self.unit, invocation_id='run-two')
        self.assertEqual(record['replacesNotificationId'], 17)
        self.assertIn('--replace-id', self.notification_commands[-1])
        self.server = 'another-bus|:1.15'
        record = self.notifier.alert(self.unit, invocation_id='run-three')
        self.assertNotIn('replacesNotificationId', record)
        self.assertNotIn('--replace-id', self.notification_commands[-1])
        self.server = 'another-bus|:1.16'
        record = self.notifier.alert(self.unit, invocation_id='run-four')
        self.assertNotIn('replacesNotificationId', record)

    def test_expired_notification_id_is_not_replaced(self):
        self.notifier.alert(self.unit)
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)
        with mock.patch.object(notify_local.datetime, 'datetime', wraps=datetime.datetime) as clock:
            clock.now.return_value = later
            record = self.notifier.alert(self.unit, invocation_id='run-two')
        self.assertNotIn('replacesNotificationId', record)

    def test_unknown_server_identity_delivers_without_replacement(self):
        self.notifier.alert(self.unit)
        with mock.patch.object(self.notifier, '_notification_server_id', side_effect=RuntimeError('private')):
            record = self.notifier.alert(self.unit, invocation_id='run-two')
        self.assertTrue(record['desktopDeliveryAccepted'])
        self.assertIn('notificationServerIdentityError', record)
        self.assertNotIn('--replace-id', self.notification_commands[-1])

    def test_watch_skips_active_units_and_suppresses_repeated_failure(self):
        with contextlib.redirect_stdout(io.StringIO()):
            first = self.notifier.watch()
            second = self.notifier.watch()
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(len(self.notification_commands), 1)

    def test_status_error_is_recorded_and_later_poll_retries(self):
        self.status[self.unit] = (subprocess.TimeoutExpired('systemctl', 10), '')
        failed = self.notifier.alert(self.unit, only_if_failed=True)
        self.assertFalse(failed['desktopDeliveryAttempted'])
        self.assertEqual(failed['statusQueryError'], 'TimeoutExpired')
        self.assertIn(self.unit, self.state()['statusErrors'])
        self.assertEqual(self.notification_commands, [])
        self.status[self.unit] = ('failed', 'run-one')
        self.assertTrue(self.notifier.alert(self.unit)['desktopDeliveryAccepted'])

    def test_healthy_status_recovery_clears_error_without_notification(self):
        self.status[self.unit] = (subprocess.TimeoutExpired('systemctl', 10), '')
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
        self.status[self.unit] = (subprocess.TimeoutExpired('systemctl', 10), '')
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


if __name__ == '__main__':
    unittest.main()
