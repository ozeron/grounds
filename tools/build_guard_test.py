#!/usr/bin/env python3
"""Exercise resource isolation with small real subprocesses, never Bend builds."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


GUARD = Path(__file__).with_name("build_guard.py")


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="grounds-guard-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.lock = self.directory / "lock"

    def command(self, name, code, memory=256, timeout=5):
        report = self.directory / f"{name}.json"
        command = [sys.executable, str(GUARD), "--lock", str(self.lock),
                   "--report", str(report)]
        if memory is not None:
            command.extend(["--memory-mib", str(memory)])
        command.extend(["--timeout", str(timeout), "--", sys.executable, "-c", code])
        return command, report

    def run_job(self, name, code, memory=256, timeout=5):
        command, report = self.command(name, code, memory, timeout)
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        evidence = json.loads(report.read_text())
        self.assertEqual(result.returncode, evidence["exit_code"], result.stderr)
        return evidence

    def wait_file(self, path):
        deadline = time.monotonic() + 5
        while not path.exists():
            if time.monotonic() > deadline:
                self.fail(f"Child did not create {path}")
            time.sleep(0.02)

    def stop_process(self, process):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)

    def assert_stopped(self, pids):
        deadline = time.monotonic() + 3
        while True:
            result = subprocess.run(["ps", "-o", "pid=,stat=", "-p",
                                     ",".join(map(str, pids))], capture_output=True, text=True)
            live = [line for line in result.stdout.splitlines()
                    if "Z" not in line.split()[1]]
            if not live:
                return
            if time.monotonic() > deadline:
                self.fail(f"Owned children survived: {live}")
            time.sleep(0.02)

    def spawn_code(self, count, size, marker):
        child = f"import time; data=bytearray({size}*1024*1024); time.sleep(30)"
        return (
            "import subprocess,sys,time,json,pathlib,os; "
            f"children=[subprocess.Popen([sys.executable,'-c',{child!r}]) for _ in range({count})]; "
            f"pathlib.Path({str(marker)!r}).write_text(json.dumps([os.getpid()]+[p.pid for p in children])); "
            "time.sleep(30)"
        )

    def test_success_and_single_moon_worker(self):
        report = self.run_job("success", "import os,time; "
                              "assert os.environ['MOON_CONCURRENCY']=='1'; time.sleep(.2)",
                              memory=None)
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["reason"], "child-exit")
        self.assertEqual(report["memory_limit_bytes"], 512 * 1024 * 1024)
        self.assertGreater(report["peak_bytes"], 0)
        if sys.platform == "darwin":
            self.assertIn("physical-footprint", report["metric"])

    def test_failed_command_stays_failed(self):
        report = self.run_job("failure", "import sys; sys.exit(7)")
        self.assertEqual(report["exit_code"], 7)

    def test_aggregate_child_memory_cutoff_preserves_unrelated_process(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(self.stop_process, unrelated)
        marker = self.directory / "pids.json"
        report = self.run_job("aggregate", self.spawn_code(2, 24, marker), memory=64)
        self.assertEqual(report["reason"], "memory-cutoff")
        self.assertEqual(report["exit_code"], 137)
        self.assertGreater(report["peak_bytes"], 64 * 1024 * 1024)
        self.assertGreaterEqual(len(report["peak_processes"]), 3)
        self.assert_stopped(json.loads(marker.read_text()))
        self.assertIsNone(unrelated.poll())

    def test_timeout_kills_children_ignoring_term(self):
        marker = self.directory / "pids.json"
        code = self.spawn_code(1, 0, marker).replace(
            "import time; data", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); data"
        )
        report = self.run_job("timeout", code, timeout=0.5)
        self.assertEqual(report["reason"], "timeout")
        self.assertEqual(report["exit_code"], 124)
        self.assert_stopped(json.loads(marker.read_text()))

    def test_overlap_refused_then_lock_released(self):
        marker = self.directory / "started"
        code = f"import pathlib,time; pathlib.Path({str(marker)!r}).touch(); time.sleep(.8)"
        command, first_report = self.command("first", code)
        first = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_process, first)
        self.wait_file(marker)
        second = self.run_job("second", "raise RuntimeError('must not launch')")
        self.assertEqual(second["reason"], "another-guarded-job-is-running")
        self.assertEqual(first.wait(timeout=5), 0, first_report.read_text())
        third = self.run_job("third", "pass")
        self.assertEqual(third["exit_code"], 0)

    def test_interrupt_cleans_up_group(self):
        marker = self.directory / "pids.json"
        command, report_path = self.command("interrupt", self.spawn_code(1, 0, marker))
        guard = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_process, guard)
        self.wait_file(marker)
        guard.send_signal(signal.SIGTERM)
        self.assertEqual(guard.wait(timeout=5), 143)
        self.assertEqual(json.loads(report_path.read_text())["reason"], "signal")
        self.assert_stopped(json.loads(marker.read_text()))

    def test_leftover_child_fails_and_is_stopped(self):
        marker = self.directory / "pids.json"
        # Keep the child alive, but let its launcher exit after writing the PID list.
        code = self.spawn_code(1, 0, marker).rsplit("time.sleep(30)", 1)[0] + "time.sleep(.2)"
        report = self.run_job("orphan", code)
        self.assertEqual(report["reason"], "leftover-children")
        self.assertEqual(report["exit_code"], 125)
        self.assert_stopped(json.loads(marker.read_text()))

    def test_missing_command_fails_closed(self):
        command, report_path = self.command("missing", "pass")
        command[-3:] = [str(self.directory / "missing-executable")]
        result = subprocess.run(command, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 125)
        self.assertEqual(json.loads(report_path.read_text())["reason"], "guard-error")


if __name__ == "__main__":
    unittest.main()
