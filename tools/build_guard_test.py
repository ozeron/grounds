#!/usr/bin/env python3
"""Exercise resource isolation with small real subprocesses, never Bend builds."""

import ctypes
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


GUARD = Path(__file__).with_name("build_guard.py")
SystemPressure = runpy.run_path(str(GUARD))["SystemPressure"]


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
        if timeout is not None:
            command.extend(["--timeout", str(timeout)])
        command.extend(["--", sys.executable, "-c", code])
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

    def pressure_command(self, name, code, reader):
        command, report = self.command(name, code)
        # Patch only the pressure observation in a separate guard process.
        # Its lock, real child/process-group monitoring and cleanup still run.
        wrapper = (
            "import pathlib,runpy,sys; from unittest import mock; "
            f"namespace=runpy.run_path({str(GUARD)!r}); "
            f"sys.argv={command[1:]!r}; "
            f"reader={reader}; "
            "patch=mock.patch.object(namespace['SystemPressure'],'read',side_effect=reader); "
            "patch.start(); sys.exit(namespace['main']())"
        )
        return [sys.executable, "-c", wrapper], report

    def test_success_and_single_moon_worker(self):
        report = self.run_job("success", "import os,time; "
                              "assert os.environ['MOON_CONCURRENCY']=='1'; time.sleep(.2)",
                              memory=None, timeout=None)
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["reason"], "child-exit")
        self.assertEqual(report["memory_limit_bytes"], 384 * 1024 * 1024)
        self.assertEqual(report["process_memory_limit_bytes"], 320 * 1024 * 1024)
        self.assertEqual(report["timeout_seconds"], 120)
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

    def test_individual_child_cutoff_below_aggregate_limit(self):
        marker = self.directory / "pids.json"
        command, report_path = self.command("individual", self.spawn_code(1, 56, marker))
        separator = command.index("--")
        command[separator:separator] = ["--process-memory-mib", "48"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        report = json.loads(report_path.read_text())
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertEqual(report["reason"], "process-memory-cutoff")
        self.assertLess(report["peak_bytes"], 256 * 1024 * 1024)
        sizes = report["peak_process_memory_bytes"].values()
        self.assertEqual(sum(sizes), report["peak_bytes"])
        self.assertGreater(max(sizes), 48 * 1024 * 1024)
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

    def test_pressure_before_launch_refuses_work(self):
        for level in ("warning", "critical"):
            with self.subTest(level=level):
                marker = self.directory / f"{level}-started"
                command, path = self.pressure_command(
                    f"pre-{level}", f"import pathlib; pathlib.Path({str(marker)!r}).touch()",
                    f"lambda: {level!r}",
                )
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                report = json.loads(path.read_text())
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertEqual(report["reason"], "system-memory-pressure-before-launch")
                self.assertEqual(report["system_pressure"], level)
                self.assertNotIn("pid", report)
                self.assertFalse(marker.exists())

    def test_pressure_during_job_stops_owned_group_only(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(self.stop_process, unrelated)
        for level in ("warning", "critical"):
            with self.subTest(level=level):
                marker = self.directory / f"{level}-pids.json"
                code = self.spawn_code(1, 0, marker).replace(
                    "import time; data",
                    "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); data",
                )
                reader = f"lambda: {level!r} if pathlib.Path({str(marker)!r}).exists() else 'normal'"
                command, path = self.pressure_command(f"running-{level}", code, reader)
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                report = json.loads(path.read_text())
                self.assertEqual(result.returncode, 137, result.stderr)
                self.assertEqual(report["reason"], "system-memory-pressure")
                self.assertEqual(report["system_pressure"], level)
                self.assertGreaterEqual(report["system_pressure_samples"], 2)
                self.assertLess(report["peak_bytes"], 256 * 1024 * 1024)
                self.assert_stopped(json.loads(marker.read_text()))
                self.assertIsNone(unrelated.poll())

    def test_pressure_measurement_error_fails_closed_and_cleans_up(self):
        marker = self.directory / "pressure-error-pids.json"
        reader = (
            f"lambda: (_ for _ in ()).throw(OSError('pressure unavailable')) "
            f"if pathlib.Path({str(marker)!r}).exists() else 'normal'"
        )
        command, path = self.pressure_command("pressure-error", self.spawn_code(1, 0, marker), reader)
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        report = json.loads(path.read_text())
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertEqual(report["reason"], "guard-error")
        self.assertIn("pressure unavailable", report["error"])
        self.assert_stopped(json.loads(marker.read_text()))

    @unittest.skipUnless(sys.platform == "darwin", "macOS sysctl only")
    def test_native_pressure_decoding_and_invalid_observations(self):
        pressure = SystemPressure()
        for value, expected in ((1, "normal"), (2, "warning"), (4, "critical"), (3, None)):
            with self.subTest(value=value):
                def observation(_name, output, _size, new_value, new_size):
                    self.assertIsNone(new_value)
                    self.assertEqual(new_size, 0)
                    ctypes.cast(output, ctypes.POINTER(ctypes.c_uint32))[0] = value
                    return 0
                with mock.patch.object(pressure.lib, "sysctlbyname", side_effect=observation):
                    if expected is None:
                        with self.assertRaisesRegex(RuntimeError, "Unrecognized system memory pressure"):
                            pressure.read()
                    else:
                        self.assertEqual(pressure.read(), expected)
        with mock.patch.object(pressure.lib, "sysctlbyname", return_value=-1):
            with self.assertRaisesRegex(OSError, "Cannot measure system memory pressure"):
                pressure.read()
        def short_read(_name, _output, size, _new, _new_size):
            ctypes.cast(size, ctypes.POINTER(ctypes.c_size_t))[0] = 1
            return 0
        with mock.patch.object(pressure.lib, "sysctlbyname", side_effect=short_read):
            with self.assertRaisesRegex(RuntimeError, "pressure byte count"):
                pressure.read()


if __name__ == "__main__":
    unittest.main()
