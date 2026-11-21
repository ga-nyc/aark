#!/usr/bin/env python3
"""Linux desktop notification adapter with durable, serialized delivery state.

This adapter reads only systemd unit properties, the kernel boot identifier,
and its own redacted delivery bookkeeping. It never reads evidence or scanner
logs, and never starts, stops, restarts, or signals a scanner. Configure an
explicit unit allowlist and desktop session before use. Notification acceptance
is not user acknowledgement.
"""
import argparse
import contextlib
import datetime
try:
    import fcntl
except ImportError:  # The adapter is Linux-only; importing remains harmless.
    fcntl = None
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import unquote_to_bytes

EVENTS = {'failed', 'paused', 'complete', 'notification-test'}
NOTIFICATION_TIMEOUT_MS = 15000
DEFAULT_STATE_DIRECTORY = Path('/var/lib/aark-alerts')
UNIT_STEM_PATTERN = r'(?:[A-Za-z0-9_@.:-]|\\x[0-9a-fA-F]{2})+'
COMMAND_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _key(unit, invocation_id, event):
    return '|'.join((unit, invocation_id, event))


def _error(exc):
    # Never copy arbitrary subprocess output or local file contents into alerts.
    return type(exc).__name__


def _unit_stem(unit):
    if not isinstance(unit, str):
        raise ValueError('Unknown alert identifier')
    return unit[:-8] if unit.endswith('.service') else unit


def _valid_unit_stem(unit):
    return (isinstance(unit, str) and re.fullmatch(UNIT_STEM_PATTERN, unit) is not None
            and not unit.startswith('-'))


def _boot_id():
    fd = os.open('/proc/sys/kernel/random/boot_id', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r', encoding='ascii') as stream:
        value = stream.read(38)
    if (not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n?', value)
            or value.rstrip('\n') == '00000000-0000-0000-0000-000000000000'):
        raise RuntimeError('Kernel boot identity unavailable')
    return value.rstrip('\n')


def _local_bus_address(value):
    # D-Bus permits semicolon-separated transports. Accept one connectable
    # Unix endpoint only, using the specification's escaped-value grammar.
    if not isinstance(value, str) or not value.startswith('unix:'):
        return False
    properties = {}
    for item in value[5:].split(','):
        key, separator, encoded = item.partition('=')
        if (not separator or key not in ('path', 'abstract', 'guid') or key in properties
                or not re.fullmatch(r'(?:[-0-9A-Za-z_/.*]|%[0-9a-fA-F]{2})+', encoded)):
            return False
        decoded = unquote_to_bytes(encoded)
        if any(byte < 32 or byte == 127 for byte in decoded):
            return False
        properties[key] = decoded
    endpoints = set(properties).intersection(('path', 'abstract'))
    if len(endpoints) != 1:
        return False
    if 'path' in properties and not properties['path'].startswith(b'/'):
        return False
    if 'guid' in properties and not re.fullmatch(b'[0-9a-fA-F]{32}', properties['guid']):
        return False
    return True


def _validate_identifiers(unit, event, invocation_id=None):
    # Stored unit names are already normalized stems. Schema validation must
    # neither normalize them again nor depend on the current authorization.
    if (not _valid_unit_stem(unit) or not isinstance(event, str) or event not in EVENTS):
        raise ValueError('Unknown alert identifier')
    if invocation_id is not None and (not isinstance(invocation_id, str)
            or not re.fullmatch(r'[A-Za-z0-9:_-]{1,160}', invocation_id)):
        raise ValueError('Invalid invocation identifier')


def _historical_time(value):
    # Imported history is not trusted redacted text. Accept only an explicit
    # ISO timestamp and publish a freshly formatted UTC value.
    if not isinstance(value, str) or not re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
            r'(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})', value):
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(
            datetime.timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


class LocalNotifier:
    """A host adapter. Construction does not access files or invoke processes."""

    def __init__(self, *, allow_units, session_user, bus_address,
                 state_directory=DEFAULT_STATE_DIRECTORY, historical_journal=None):
        if fcntl is None:
            raise ValueError('Local desktop notification delivery requires Linux')
        if isinstance(allow_units, str):
            raise ValueError('The unit allowlist must be a collection of unit names')
        self.allowed = {_unit_stem(unit) for unit in allow_units}
        if not self.allowed or any(not _valid_unit_stem(unit) for unit in self.allowed):
            raise ValueError('Configure an explicit allowlist of systemd unit names')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*[$]?', session_user):
            raise ValueError('Configure a valid desktop session user')
        if not _local_bus_address(bus_address):
            raise ValueError('Configure the local desktop session bus address')
        self.root = Path(state_directory)
        self.historical_journal = Path(historical_journal) if historical_journal else None
        self.bus_address = bus_address
        self.user_command = ['/usr/sbin/runuser', '-u', session_user, '--',
                             '/usr/bin/env', 'DBUS_SESSION_BUS_ADDRESS=' + bus_address]

    def _identifiers(self, unit, event, invocation_id=None):
        unit = _unit_stem(unit)
        _validate_identifiers(unit, event, invocation_id)
        if unit not in self.allowed:
            raise ValueError('Unknown alert identifier')
        return unit

    def _private_open(self, path, flags):
        fd = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError('Delivery bookkeeping must be a regular file')
            os.fchmod(fd, 0o600)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _sync_directory(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _locked(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise OSError('Delivery directory must be owned by the notifier')
        os.chmod(self.root, 0o700)
        fd = self._private_open(self.root / 'delivery.lock', os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _append_record(self, record):
        fd = self._private_open(self.root / 'alerts-redacted.ndjson', os.O_RDWR | os.O_APPEND | os.O_CREAT)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            size = os.fstat(stream.fileno()).st_size
            if size and os.pread(stream.fileno(), 1, size - 1) != b'\n':
                # Preserve an interrupted tail, but keep it separate so journal
                # replay can still recover this independently durable receipt.
                stream.write('\n')
            stream.write(json.dumps(record, sort_keys=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        self._sync_directory()

    def _save_state(self, state):
        fd, name = tempfile.mkstemp(prefix='.delivery-state-', dir=self.root)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(state, stream, sort_keys=True)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.root / 'delivery-state.json')
            self._sync_directory()
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _journal_records(self, path, private=False):
        try:
            fd = self._private_open(path, os.O_RDONLY) if private else os.open(
                path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            return
        with os.fdopen(fd, 'rb') as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except (ValueError, UnicodeError):
                    continue  # A truncated final line cannot establish delivery.
                if isinstance(record, dict):
                    yield record

    def _remember(self, state, record):
        if not self._valid_delivery(record):
            return
        key = record['deliveryKey']
        old = state['deliveries'].get(key)
        # The cache may be newer when a journal append failed. Acceptance is
        # authoritative at every attempt count; otherwise preserve the highest
        # durable attempt and keep equal-attempt replay idempotent.
        if (old is None
                or (record['desktopDeliveryAccepted'] and not old['desktopDeliveryAccepted'])
                or (record['desktopDeliveryAccepted'] == old['desktopDeliveryAccepted']
                    and record['attempt'] > old['attempt'])):
            state['deliveries'][key] = record

    def _valid_delivery(self, record):
        try:
            _validate_identifiers(record['unit'], record['event'], record['invocationId'])
            return (record.get('version') == 2
                    and record['deliveryKey'] == _key(record['unit'], record['invocationId'], record['event'])
                    and isinstance(record.get('desktopDeliveryAccepted'), bool)
                    and isinstance(record.get('attempt'), int) and record['attempt'] >= 0)
        except (AttributeError, KeyError, TypeError, ValueError):
            return False

    def _load_state(self):
        # Keep accepting the legacy notifications cache, but never use its IDs
        # for replacement: independent bus probes cannot bind notify-send to it.
        state = {'version': 2, 'deliveries': {}, 'notifications': {}, 'statusErrors': {}}
        warning = None
        try:
            fd = self._private_open(self.root / 'delivery-state.json', os.O_RDONLY)
            with os.fdopen(fd, 'r', encoding='utf-8') as stream:
                loaded = json.load(stream)
            if (loaded.get('version') != 2
                    or any(not isinstance(loaded.get(k), dict)
                           for k in ('deliveries', 'notifications', 'statusErrors'))
                    or any(not self._valid_delivery(record) or key != record['deliveryKey']
                           for key, record in loaded['deliveries'].items())
                    or any(not isinstance(record, dict)
                           for record in loaded['notifications'].values())):
                raise ValueError('Unsupported delivery state')
            state = loaded
        except FileNotFoundError:
            pass
        except (ValueError, UnicodeError, AttributeError) as exc:
            warning = _error(exc)
        # Recover accepted deliveries if a crash occurred after the journal fsync
        # but before the state replacement. Legacy rows require an explicit seed.
        for record in self._journal_records(self.root / 'alerts-redacted.ndjson', private=True):
            if self._valid_delivery(record):
                self._remember(state, record)
        return state, warning

    def _persist(self, state, record):
        self._remember(state, record)
        journal_written = False
        try:
            self._append_record(record)
            journal_written = True
        except OSError as exc:
            record['journalPersistenceError'] = _error(exc)
        try:
            self._save_state(state)
        except OSError as exc:
            record['statePersistenceError'] = _error(exc)
            if journal_written:
                try:
                    self._append_record(record)
                except OSError:
                    pass
        return record

    def _unit_status(self, unit):
        result = subprocess.run(
            ['/usr/bin/systemctl', 'show', unit + '.service', '--no-pager',
             '-p', 'ActiveState', '-p', 'InvocationID',
             '-p', 'ExecMainStartTimestampMonotonic', '-p', 'ExecMainExitTimestampMonotonic'],
            capture_output=True, text=True, timeout=10, env=COMMAND_ENV)
        if result.returncode:
            raise RuntimeError('systemctl status query failed')
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        active = fields.get('ActiveState')
        if not active:
            raise RuntimeError('systemctl status query omitted ActiveState')
        invocation_id = fields.get('InvocationID', '')
        if not invocation_id:
            start = fields.get('ExecMainStartTimestampMonotonic', '0')
            end = fields.get('ExecMainExitTimestampMonotonic', '0')
            if (re.fullmatch(r'[0-9]{1,20}', start) and re.fullmatch(r'[0-9]{1,20}', end)
                    and 0 < int(start) <= 0xffffffffffffffff and int(end) <= 0xffffffffffffffff):
                invocation_id = 'systemd-' + _boot_id() + '-' + start + '-' + end
        return active, invocation_id

    def _deliver(self, state, unit, event, invocation_id, state_warning=None):
        key = _key(unit, invocation_id, event)
        previous = state['deliveries'].get(key, {})
        if previous.get('desktopDeliveryAccepted'):
            return None
        record = {
            'version': 2, 'unit': unit, 'event': event, 'invocationId': invocation_id,
            'deliveryKey': key, 'time': _now(), 'attempt': previous.get('attempt', 0) + 1,
            'desktopDeliveryAttempted': True, 'desktopDeliveryAccepted': False,
            'userAcknowledged': False, 'urgency': 'normal',
            'expireTimeoutMs': NOTIFICATION_TIMEOUT_MS,
        }
        if state_warning:
            record['stateRecoveredAfterError'] = state_warning
        command = self.user_command + [
            '/usr/bin/notify-send', '--print-id', '-u', 'normal',
            '-t', str(NOTIFICATION_TIMEOUT_MS), '-a', 'AARK']
        command += ['AARK: ' + event, unit + ': inspect the local redacted status.']
        try:
            result = subprocess.run(command, capture_output=True, text=True, errors='replace', timeout=15, env=COMMAND_ENV)
            record['desktopDeliveryAccepted'] = result.returncode == 0
            if result.returncode:
                record['deliveryError'] = 'notify-send returned ' + str(result.returncode)
            else:
                record['deliveryAcceptedTime'] = _now()
                printed_id = result.stdout.strip()
                if re.fullmatch(r'[0-9]{1,10}', printed_id):
                    notification_id = int(printed_id)
                    if 0 < notification_id <= 0xffffffff:
                        record['notificationId'] = notification_id
                if 'notificationId' not in record:
                    record['notificationIdError'] = 'No valid notification ID returned'
        except (OSError, subprocess.SubprocessError) as exc:
            record['deliveryError'] = _error(exc)
        return self._persist(state, record)

    def _status_recovered(self, state, unit, active):
        if state['statusErrors'].pop(unit, None) is None:
            return None
        return self._persist(state, {
            'version': 2, 'unit': unit, 'event': 'status-recovered', 'time': _now(),
            'activeState': active, 'statusQuerySucceeded': True,
            'desktopDeliveryAttempted': False, 'desktopDeliveryAccepted': False,
            'userAcknowledged': False,
        })

    def alert(self, unit, event='failed', invocation_id=None, only_if_failed=False):
        """Attempt once per invocation/event; return a record, or None if suppressed.

        Failed delivery is recorded and retried by a later call. Passing an
        invocation_id is intended for testing or an explicitly known invocation.
        """
        unit = self._identifiers(unit, event, invocation_id)
        try:
            with self._locked():
                state, warning = self._load_state()
                if invocation_id is None:
                    try:
                        active, invocation_id = self._unit_status(unit)
                        if (only_if_failed or event == 'failed') and active != 'failed':
                            return self._status_recovered(state, unit, active)
                        if not invocation_id:
                            raise RuntimeError('No stable systemd invocation identifier')
                        _validate_identifiers(unit, event, invocation_id)
                        self._status_recovered(state, unit, active)
                    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                        record = {
                            'version': 2, 'unit': unit, 'event': event, 'time': _now(),
                            'desktopDeliveryAttempted': False, 'desktopDeliveryAccepted': False,
                            'userAcknowledged': False, 'statusQueryError': _error(exc),
                        }
                        state['statusErrors'][unit] = record
                        return self._persist(state, record)
                return self._deliver(state, unit, event, invocation_id, warning)
        except (OSError, ValueError) as exc:
            return {
                'version': 2, 'unit': unit, 'event': event, 'time': _now(),
                'desktopDeliveryAttempted': False, 'desktopDeliveryAccepted': False,
                'userAcknowledged': False, 'deliveryInfrastructureError': _error(exc),
            }

    def on_failure(self, unit, invocation_id):
        """Deliver for the triggering invocation supplied by systemd, not its successor."""
        if not isinstance(invocation_id, str) or not re.fullmatch(r'[a-f0-9]{32}', invocation_id):
            raise ValueError('A systemd failure handler requires its monitored invocation identifier')
        return self.alert(unit, 'failed', invocation_id=invocation_id)

    def seed_accepted_history(self, unit, invocation_id, event='failed'):
        """Suppress a known invocation using accepted historical delivery, without a popup.

        The caller must establish which invocation the historical rows concern.
        This records desktop acceptance only; it never records user acknowledgement.
        """
        unit = self._identifiers(unit, event, invocation_id)
        if self.historical_journal is None:
            raise ValueError('Configure the accepted historical alerts journal before seeding')
        with self._locked():
            state, _ = self._load_state()
            key = _key(unit, invocation_id, event)
            if state['deliveries'].get(key, {}).get('desktopDeliveryAccepted'):
                return None
            accepted = [record for record in self._journal_records(self.historical_journal)
                        if record.get('unit') == unit and record.get('event') == event
                        and record.get('desktopDeliveryAccepted') is True]
            if not accepted:
                raise ValueError('No accepted historical alert exists for this unit/event')
            record = {
                'version': 2, 'unit': unit, 'event': event, 'invocationId': invocation_id,
                'deliveryKey': key, 'time': _now(), 'attempt': 0,
                'desktopDeliveryAttempted': False, 'desktopDeliveryAccepted': True,
                'userAcknowledged': False, 'seededFromAcceptedHistory': True,
                'historicalAcceptedCount': len(accepted),
            }
            historical_time = _historical_time(accepted[-1].get('time'))
            if historical_time is not None:
                record['historicalLatestTime'] = historical_time
            return self._persist(state, record)

    def watch(self):
        # Independent timer; status/delivery problems never change scanner state.
        records = []
        attempted = set()
        for unit in sorted(self.allowed):
            record = self.alert(unit + '.service', only_if_failed=True)
            if record is not None:
                records.append(record)
                if record.get('desktopDeliveryAttempted') and record.get('deliveryKey'):
                    attempted.add(record['deliveryKey'])
                print(json.dumps(record, sort_keys=True), flush=True)
        # A failed invocation may already have restarted. Retry its persisted
        # receipt independently of the current status, with at most one extra
        # desktop attempt per pass and no second attempt for a just-polled key.
        record = self._retry_failed_delivery(attempted)
        if record is not None:
            records.append(record)
            print(json.dumps(record, sort_keys=True), flush=True)
        return records

    def _retry_failed_delivery(self, attempted):
        try:
            with self._locked():
                state, warning = self._load_state()
                pending = (record for key, record in state['deliveries'].items()
                           if key not in attempted and record['unit'] in self.allowed
                           and record['event'] == 'failed'
                           and record.get('desktopDeliveryAttempted') is True
                           and record['desktopDeliveryAccepted'] is False)
                # Lowest attempt count prevents one unavailable delivery from
                # permanently starving other known undelivered failures.
                record = min(pending, key=lambda row: (row['attempt'], row['deliveryKey']), default=None)
                if record is None:
                    return None
                return self._deliver(state, record['unit'], 'failed', record['invocationId'], warning)
        except (OSError, ValueError) as exc:
            return {
                'version': 2, 'event': 'failed', 'time': _now(),
                'desktopDeliveryAttempted': False, 'desktopDeliveryAccepted': False,
                'userAcknowledged': False, 'deliveryInfrastructureError': _error(exc),
            }


def delivery_failed(record):
    if record is None:
        return False  # An accepted delivery was already deduplicated.
    if any(key in record for key in ('statusQueryError', 'deliveryInfrastructureError',
                                     'journalPersistenceError', 'statePersistenceError',
                                     'deliveryError')):
        return True
    return not (record.get('desktopDeliveryAccepted') is True
                or record.get('statusQuerySucceeded') is True)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-directory', type=Path, default=DEFAULT_STATE_DIRECTORY)
    parser.add_argument('--allow-unit', action='append', required=True,
                        help='Allowed systemd service; repeat for each permitted unit')
    parser.add_argument('--session-user', required=True)
    parser.add_argument('--bus-address', required=True,
                        help='Explicit unix: address of the desktop session bus')
    parser.add_argument('--historical-journal', type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--unit')
    action.add_argument('--watch', action='store_true')
    action.add_argument('--on-failure', action='store_true',
                        help='Use systemd MONITOR_UNIT and MONITOR_INVOCATION_ID from OnFailure=')
    action.add_argument('--retry-pending-failure', action='store_true',
                        help='Retry at most one persisted unaccepted failure without querying systemd')
    parser.add_argument('--event', choices=sorted(EVENTS), default='failed')
    identity = parser.add_mutually_exclusive_group()
    identity.add_argument('--seed-accepted-history', metavar='INVOCATION',
                          help='Seed a known unit invocation from accepted historical rows')
    identity.add_argument('--invocation-id', metavar='IDENTIFIER',
                          help='Explicit stable redacted event token; requires --unit')
    args = parser.parse_args(arguments)
    if args.seed_accepted_history and (not args.unit or not args.historical_journal):
        parser.error('--seed-accepted-history requires --unit and --historical-journal')
    if args.invocation_id is not None and not args.unit:
        parser.error('--invocation-id requires --unit')
    if (args.on_failure or args.retry_pending_failure) and args.event != 'failed':
        parser.error('Failure delivery actions require the failed event')
    notifier = LocalNotifier(allow_units=args.allow_unit, session_user=args.session_user,
                             bus_address=args.bus_address, state_directory=args.state_directory,
                             historical_journal=args.historical_journal)
    if args.watch:
        return int(any(delivery_failed(record) for record in notifier.watch()))
    if args.retry_pending_failure:
        record = notifier._retry_failed_delivery(set())
    elif args.on_failure:
        try:
            record = notifier.on_failure(os.environ.get('MONITOR_UNIT'), os.environ.get('MONITOR_INVOCATION_ID'))
        except ValueError:
            parser.error('--on-failure requires an allowed MONITOR_UNIT and valid MONITOR_INVOCATION_ID')
    elif args.seed_accepted_history:
        record = notifier.seed_accepted_history(args.unit, args.seed_accepted_history, args.event)
    else:
        record = notifier.alert(args.unit, args.event, invocation_id=args.invocation_id)
    if record is not None:
        print(json.dumps(record, sort_keys=True), flush=True)
    return int(delivery_failed(record))


if __name__ == '__main__':
    sys.exit(main())
