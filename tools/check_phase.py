#!/usr/bin/env python3
"""Ordered phase announcements for build_guard; clocks belong to the guard."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import time


IDLE_TIMEOUT = 10.0


class PhaseError(RuntimeError):
    pass


class Phases:
    def __init__(self, manifest, timeout, report):
        raw = manifest.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {'version', 'phases'} or value['version'] != 1:
            raise PhaseError('Unrecognized phase manifest')
        self.expected = value['phases']
        if not isinstance(self.expected, list) or not self.expected:
            raise PhaseError('A nonempty phase sequence is required')
        names = []
        for phase in self.expected:
            if (not isinstance(phase, dict) or set(phase) != {'name', 'optional'}
                    or not isinstance(phase['name'], str)
                    or re.fullmatch(r'[a-z0-9][a-z0-9_/-]{0,99}', phase['name']) is None
                    or type(phase['optional']) is not bool):
                raise PhaseError('Invalid phase declaration')
            names.append(phase['name'])
        if len(names) != len(set(names)):
            raise PhaseError('Duplicate phase declarations')
        self.timeout = timeout
        self.report = report
        report.update(phase_manifest_sha256=hashlib.sha256(raw).hexdigest(),
                      phase_manifest=value, timeout_scope='each-declared-phase',
                      phase_idle_timeout_seconds=IDLE_TIMEOUT, phases=[])
        self.index = 0
        self.active = None
        self.since = time.monotonic()
        self.temporary = tempfile.TemporaryDirectory(prefix='grounds-phase-', dir='/tmp')
        self.address = str(Path(self.temporary.name) / 'guard')
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.socket.bind(self.address)
        self.socket.setblocking(False)

    def close(self):
        self.socket.close()
        self.temporary.cleanup()

    def expired(self, now):
        limit = self.timeout if self.active is not None else IDLE_TIMEOUT
        return now - self.since > limit

    def observe(self, size):
        if self.active is not None:
            self.active['peak_bytes'] = max(self.active['peak_bytes'], size)

    def event(self, value, now):
        if self.index >= len(self.expected):
            raise PhaseError('Event after the final phase')
        phase = self.expected[self.index]
        if not isinstance(value, dict) or value.get('phase') != phase['name']:
            raise PhaseError('Unexpected or out-of-order phase')
        kind = value.get('event')
        if kind == 'start' and set(value) == {'event', 'phase'}:
            if self.active is not None:
                raise PhaseError('Overlapping or repeated phase start')
            self.active = {'name': phase['name'], 'status': 'running', 'peak_bytes': 0}
            self.report['phases'].append(self.active)
            self.since = now
        elif kind == 'end' and set(value) == {'event', 'phase', 'status'}:
            if self.active is None or type(value['status']) is not int or not 0 <= value['status'] <= 255:
                raise PhaseError('Invalid phase completion')
            self.active.update(status='passed' if value['status'] == 0 else 'failed',
                               exit_code=value['status'], elapsed_seconds=round(now - self.since, 3))
            if value['status']:
                raise PhaseError('Phase command failed')
            self.active = None
            self.index += 1
            self.since = now
        elif kind == 'skip' and set(value) == {'event', 'phase', 'reason'}:
            if (self.active is not None or not phase['optional'] or not isinstance(value['reason'], str)
                    or not 1 <= len(value['reason']) <= 200):
                raise PhaseError('Invalid or forbidden phase skip')
            self.report['phases'].append({'name': phase['name'], 'status': 'skipped', 'reason': value['reason']})
            self.index += 1
            self.since = now
        else:
            raise PhaseError('Malformed phase event')

    def poll(self, now):
        try:
            raw, address = self.socket.recvfrom(4097)
        except BlockingIOError:
            return
        try:
            if len(raw) > 4096:
                raise PhaseError('Oversized phase event')
            self.event(json.loads(raw), now)
        except (ValueError, PhaseError) as error:
            self.socket.sendto(str(error).encode(), address)
            raise PhaseError(str(error)) from error
        self.socket.sendto(b'ok', address)

    def finish(self):
        if self.active is not None or self.index != len(self.expected):
            raise PhaseError('Missing or unfinished phases')


def announce(arguments):
    if len(arguments) not in (2, 3) or arguments[0] not in ('start', 'end', 'skip'):
        raise PhaseError('Usage: check_phase.py start NAME | end NAME STATUS | skip NAME REASON')
    event, phase = arguments[:2]
    value = {'event': event, 'phase': phase}
    if event == 'end':
        value['status'] = int(arguments[2])
    elif event == 'skip':
        value['reason'] = arguments[2]
    elif len(arguments) != 2:
        raise PhaseError('A phase start takes no status')
    address = os.environ.get('GROUNDS_CHECK_PHASE_SOCKET')
    if address:
        with tempfile.TemporaryDirectory(prefix='grounds-event-', dir='/tmp') as temporary:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
                client.bind(str(Path(temporary) / 'client'))
                client.settimeout(5)
                client.sendto(json.dumps(value).encode(), address)
                response = client.recv(4096)
                if response != b'ok':
                    raise PhaseError(response.decode())
    if event == 'start':
        print(f'Check phase: {phase}', flush=True)
    elif event == 'skip':
        print(f'Check phase skipped: {phase}: {value["reason"]}', flush=True)


if __name__ == '__main__':
    try:
        announce(sys.argv[1:])
    except (IndexError, ValueError, OSError, PhaseError) as error:
        print(f'Check phase: {error}', file=sys.stderr)
        sys.exit(125)
