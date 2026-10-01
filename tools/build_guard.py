#!/usr/bin/env python3
"""Run one local build/check with an aggregate process-group memory cutoff."""

import argparse
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


MIB = 1024 * 1024


class Usage(ctypes.Structure):
    # macOS SDK sys/resource.h: rusage_info_v0, proc_pid_rusage flavor 0.
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
        (name, ctypes.c_uint64) for name in (
            "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups",
            "pageins", "wired_size", "resident_size", "phys_footprint",
            "proc_start_abstime", "proc_exit_abstime",
        )
    ]


class Memory:
    def __init__(self):
        self.metric = "aggregate-rss"
        self.lib = None
        if sys.platform == "darwin":
            self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            self.lib.proc_pid_rusage.argtypes = [
                ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
            ]
            self.lib.proc_pid_rusage.restype = ctypes.c_int
            self.metric = "aggregate-max-rss-physical-footprint"
            self.read(os.getpid(), 0)  # Fail before launching if unavailable.
        elif not sys.platform.startswith("linux"):
            raise RuntimeError("Memory measurement supports macOS and Linux only")

    def read(self, pid, rss):
        if self.lib is None:
            return rss
        usage = Usage()
        if self.lib.proc_pid_rusage(pid, 0, ctypes.byref(usage)) != 0:
            code = ctypes.get_errno()
            if code == errno.ESRCH:
                return 0  # Process exited between the process and memory reads.
            raise OSError(code, "Cannot measure owned process", pid)
        return max(rss, usage.phys_footprint)


def processes():
    output = subprocess.check_output(
        ["ps", "-axo", "pid=,pgid=,rss=,stat=,uid=,comm="], text=True,
        timeout=3,
    )
    rows = []
    for line in output.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            raise RuntimeError("Unrecognized process listing; refusing unmonitored work")
        pid, pgid, rss, state, uid, command = fields
        rows.append((int(pid), int(pgid), int(rss) * 1024, state,
                     int(uid), Path(command).name))
    return rows


def group_memory(pgid, memory):
    members = [row for row in processes() if row[1] == pgid and "Z" not in row[3]]
    return sum(memory.read(row[0], row[2]) for row in members), [r[0] for r in members]


def stop_group(pgid):
    # A cutoff must stop allocations immediately, including children ignoring TERM.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-mib", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=3600)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=(
        Path.home() / ".cache" / "grounds-build.guard.lock"
    ))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.memory_mib < 1 or args.timeout <= 0:
        parser.error("A command, positive memory cutoff and timeout are required")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.lock.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    report = {
        "command": command, "cwd": str(Path.cwd()),
        "memory_limit_bytes": args.memory_mib * MIB,
        "timeout_seconds": args.timeout, "sample_interval_seconds": 0.1,
        "peak_bytes": 0, "peak_processes": [], "reason": None,
    }
    job = None
    lock = None
    exit_code = 125
    received_signal = None

    def interrupted(number, _frame):
        nonlocal received_signal
        received_signal = number

    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    try:
        lock = args.lock.open("a+")
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            report["reason"] = "another-guarded-job-is-running"
            return exit_code
        existing = [r[0] for r in processes() if r[4] == os.getuid() and r[5] == "bend"]
        if existing:
            report.update(reason="existing-bend-process", existing_bend_pids=existing)
            return exit_code
        memory = Memory()
        report["metric"] = memory.metric
        environment = dict(os.environ, MOON_CONCURRENCY="1", PYTHONDONTWRITEBYTECODE="1")
        job = subprocess.Popen(command, start_new_session=True, env=environment,
                               pass_fds=(lock.fileno(),))
        report["pid"] = job.pid
        while True:
            if received_signal is not None:
                report["reason"] = "signal"
                exit_code = 128 + received_signal
                break
            size, members = group_memory(job.pid, memory)
            report["samples"] = report.get("samples", 0) + 1
            if size > report["peak_bytes"]:
                report.update(peak_bytes=size, peak_processes=members)
            if size > report["memory_limit_bytes"]:
                report["reason"] = "memory-cutoff"
                exit_code = 137
                break
            if time.monotonic() - start > args.timeout:
                report["reason"] = "timeout"
                exit_code = 124
                break
            code = job.poll()
            if code is not None:
                _, members = group_memory(job.pid, memory)
                report["reason"] = "child-exit" if not members else "leftover-children"
                exit_code = (code if code >= 0 else 128 - code) if not members else 125
                break
            time.sleep(0.1)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(reason="guard-error", error=str(error))
    finally:
        if job is not None:
            stop_group(job.pid)
            report["child_exit_code"] = job.wait()
        if lock is not None:
            lock.close()
        report.update(exit_code=exit_code, elapsed_seconds=round(time.monotonic() - start, 3))
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Build guard: {report['reason']}; peak {report['peak_bytes'] / MIB:.1f} MiB; "
              f"report {args.report}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
