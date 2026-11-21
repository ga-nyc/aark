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
        self.assertFalse(any(command[0] == 'systemctl' for command in self.all_commands))
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
        first_line = path.read_bytes().removesuffix(b'\n')
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
