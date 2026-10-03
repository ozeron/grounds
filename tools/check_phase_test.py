#!/usr/bin/env python3
"""Phase limits, complete sequences and ownership with real small processes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

import build_guard_test as Common
from check_phase import Phases, PhaseError


class PhaseTests(unittest.TestCase):
    setUp = Common.GuardTests.setUp
    stop_process = Common.GuardTests.stop_process
    assert_stopped = Common.GuardTests.assert_stopped

    def manifest(self, optional=False):
        path = self.directory / 'phases.json'
        path.write_text(json.dumps({'version': 1, 'phases': [
            {'name': 'test/one', 'optional': optional}, {'name': 'test/two', 'optional': False}]}))
        return path

    def run_phases(self, body, memory=256, timeout=1):
        command, path = Common.GuardTests.command(self, 'phase', body, memory, timeout)
        index = command.index('--')
        command[index:index] = ['--phases', str(self.manifest())]
        result = subprocess.run(command, capture_output=True, text=True, timeout=12)
        report = json.loads(path.read_text())
        self.assertEqual(report['exit_code'], result.returncode, result.stderr)
        return report

    def program(self, body):
        return (f"import sys,time,json,subprocess,pathlib,runpy,os; "
                f"announce=runpy.run_path({str(Path(__file__).with_name('check_phase.py'))!r})['announce']; " + body)

    def test_each_phase_keeps_its_own_deadline(self):
        report = self.run_phases(self.program(
            "announce(['start','test/one']); time.sleep(.35); announce(['end','test/one','0']); "
            "announce(['start','test/two']); time.sleep(.35); announce(['end','test/two','0'])"), timeout=.5)
        self.assertEqual(report['exit_code'], 0, report)
        self.assertGreater(report['elapsed_seconds'], .5)
        self.assertEqual([p['status'] for p in report['phases']], ['passed', 'passed'])
        self.assertTrue(all(p['peak_bytes'] > 0 for p in report['phases']))

    def test_timed_out_phase_kills_owned_detached_child(self):
        marker = self.directory / 'pids.json'
        child = 'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'
        report = self.run_phases(self.program(
            "announce(['start','test/one']); "
            f"p=subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session=True); "
            f"pathlib.Path({str(marker)!r}).write_text(json.dumps([os.getpid(),p.pid])); time.sleep(30)"), timeout=.3)
        self.assertEqual(report['reason'], 'phase-timeout', report)
        self.assertEqual(report['exit_code'], 124)
        self.assert_stopped(json.loads(marker.read_text()))

    def test_memory_remains_aggregate_across_phases(self):
        marker = self.directory / 'pids.json'
        child = 'import time; data=bytearray(40*1024*1024); time.sleep(30)'
        report = self.run_phases(self.program(
            "announce(['start','test/one']); "
            f"p=subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(.2); "
            "announce(['end','test/one','0']); announce(['start','test/two']); "
            f"q=subprocess.Popen([sys.executable,'-c',{child!r}]); "
            f"pathlib.Path({str(marker)!r}).write_text(json.dumps([os.getpid(),p.pid,q.pid])); time.sleep(30)"), memory=128)
        self.assertEqual(report['reason'], 'memory-cutoff', report)
        self.assertEqual(report['exit_code'], 137)
        self.assertEqual(report['phases'][0]['status'], 'passed')
        self.assertEqual(report['phases'][1]['status'], 'running')
        self.assert_stopped(json.loads(marker.read_text()))

    def test_detached_child_memory_is_counted_and_unrelated_is_preserved(self):
        unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        self.addCleanup(self.stop_process, unrelated)
        marker = self.directory / 'pids.json'
        child = 'import time; data=bytearray(112*1024*1024); time.sleep(30)'
        report = self.run_phases(self.program(
            "announce(['start','test/one']); "
            f"p=subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session=True); "
            f"pathlib.Path({str(marker)!r}).write_text(json.dumps([os.getpid(),p.pid])); time.sleep(30)"), memory=128)
        self.assertEqual(report['reason'], 'memory-cutoff', report)
        self.assert_stopped(json.loads(marker.read_text()))
        self.assertIsNone(unrelated.poll())

    def test_overlap_order_duplicate_and_failed_completion(self):
        for body, error in [
            ("announce(['start','test/one']); announce(['start','test/one'])", 'Overlapping'),
            ("announce(['start','test/two'])", 'out-of-order'),
            ("announce(['start','test/one']); announce(['end','test/one','0']); announce(['start','test/one'])", 'out-of-order'),
            ("announce(['start','test/one']); announce(['end','test/one','7'])", 'failed'),
        ]:
            with self.subTest(body=body):
                report = self.run_phases(self.program(body))
                self.assertEqual(report['exit_code'], 125, report)
                self.assertIn(error, report['error'])

    def test_zero_exit_cannot_skip_missing_or_unfinished_phases(self):
        for body in ['pass', "announce(['start','test/one'])",
                     "announce(['start','test/one']); announce(['end','test/one','0'])"]:
            with self.subTest(body=body):
                report = self.run_phases(self.program(body))
                self.assertEqual(report['exit_code'], 125, report)
                self.assertIn('Missing or unfinished', report['error'])

    def test_declared_skip_and_idle_limit_cannot_hide_work(self):
        report = {}
        phases = Phases(self.manifest(optional=True), 120, report)
        self.addCleanup(phases.close)
        now = time.monotonic()
        with self.assertRaises(PhaseError):
            phases.event({'event': 'skip', 'phase': 'test/one', 'reason': ''}, now)
        phases.event({'event': 'skip', 'phase': 'test/one', 'reason': 'Bun unavailable'}, now)
        self.assertTrue(phases.expired(now + 10.1))
        with self.assertRaises(PhaseError):
            phases.event({'event': 'skip', 'phase': 'test/two', 'reason': 'must not skip'}, now)
        phases.event({'event': 'start', 'phase': 'test/two'}, now)
        self.assertFalse(phases.expired(now + 10.1))
        self.assertTrue(phases.expired(now + 120.1))
        phases.event({'event': 'end', 'phase': 'test/two', 'status': 0}, now + 1)
        phases.finish()
        with self.assertRaises(PhaseError):
            phases.event({'event': 'start', 'phase': 'test/two'}, now + 2)

    def test_invalid_manifest_and_longer_phase_limit_refuse_launch(self):
        command, report = Common.GuardTests.command(self, 'manifest', "raise RuntimeError('must not run')")
        index = command.index('--')
        path = self.manifest()
        value = json.loads(path.read_text())
        value['phases'].append(value['phases'][0])
        path.write_text(json.dumps(value))
        command[index:index] = ['--phases', str(path)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 125)
        self.assertIn('Duplicate', json.loads(report.read_text())['error'])
        limit = command.index('--timeout') + 1
        command[limit] = '121'
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        command[limit] = 'nan'
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
