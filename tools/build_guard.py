#!/usr/bin/env python3
"""Run local builds/checks with sampled process-tree memory and deadline limits."""

import argparse
import ctypes
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


MIB = 1024 * 1024
SAMPLE_INTERVAL = 0.02
PRESSURE_INTERVAL = 1.0


class SystemPressure:
    """Read macOS pressure notifications without changing kernel state."""

    def __init__(self):
        self.metric = "unsupported"
        self.lib = None
        if sys.platform == "darwin":
            self.lib = ctypes.CDLL(None, use_errno=True)
            self.lib.sysctlbyname.argtypes = [
                ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                ctypes.c_void_p, ctypes.c_size_t,
            ]
            self.lib.sysctlbyname.restype = ctypes.c_int
            self.metric = "kern.memorystatus_vm_pressure_level"

    def read(self):
        if self.lib is None:
            return None
        value = ctypes.c_uint32()
        size = ctypes.c_size_t(ctypes.sizeof(value))
        if self.lib.sysctlbyname(self.metric.encode(), ctypes.byref(value),
                                 ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "Cannot measure system memory pressure")
        if size.value != ctypes.sizeof(value):
            raise RuntimeError("Unrecognized system pressure byte count")
        # This sysctl returns dispatch flags, not the kernel's internal enum.
        # XNU kern_memorystatus_notify.c converts normal/warning/critical to 1/2/4.
        levels = {1: "normal", 2: "warning", 4: "critical"}
        if value.value not in levels:
            raise RuntimeError(f"Unrecognized system memory pressure: {value.value}")
        return levels[value.value]


class Usage(ctypes.Structure):
    # macOS SDK sys/resource.h: rusage_info_v0, proc_pid_rusage flavor 0.
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
        (name, ctypes.c_uint64) for name in (
            "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups",
            "pageins", "wired_size", "resident_size", "phys_footprint",
            "proc_start_abstime", "proc_exit_abstime",
        )
    ]


class BsdInfo(ctypes.Structure):
    # Installed macOS SDK sys/proc_info.h: PROC_PIDTBSDINFO, 136-byte ABI.
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'flags', 'status', 'xstatus', 'pid', 'parent', 'uid', 'gid', 'ruid',
        'rgid', 'svuid', 'svgid', 'reserved')]
    _fields_ += [('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        'nfiles', 'group', 'jobc', 'tty', 'tty_group')]
    _fields_ += [('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64),
                ('start_usec', ctypes.c_uint64)]


class ShortBsdInfo(ctypes.Structure):
    # SDK PROC_PIDT_SHORTBSDINFO, public identity/status across UIDs (64 bytes).
    _fields_ = [(name, ctypes.c_uint32) for name in ('pid', 'parent', 'group', 'status')]
    _fields_ += [('comm', ctypes.c_char * 16)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        'flags', 'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'reserved')]


class NativeProcesses:
    def __init__(self):
        self.lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.lib.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                                          ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listpids.restype = ctypes.c_int
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                         ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int

    def info(self, pid, full=True):
        value = BsdInfo() if full else ShortBsdInfo()
        ctypes.set_errno(0)
        # Short BSD metadata is public across UIDs. Full start-time metadata is
        # requested only for an owned candidate; unreadable owned work fails.
        size = self.lib.proc_pidinfo(pid, 3 if full else 13, 1,
                                     ctypes.byref(value), ctypes.sizeof(value))
        if size == 0 and ctypes.get_errno() == errno.ESRCH:
            return None
        if size != ctypes.sizeof(value):
            raise OSError(ctypes.get_errno(), 'Cannot read process identity', pid)
        if value.pid != pid:
            raise RuntimeError('Process identity ABI mismatch')
        result = {name: getattr(value, name) for name in (
            'pid', 'parent', 'group', 'uid', 'ruid', 'status')} | {
                'comm': value.comm.decode(errors='replace')}
        if full:
            result['birth'] = (value.start_sec, value.start_usec)
        return result

    def snapshot(self):
        capacity = 1024
        while capacity <= 65536:
            values = (ctypes.c_int * capacity)()
            ctypes.set_errno(0)
            size = self.lib.proc_listpids(1, 0, values, ctypes.sizeof(values))
            if size <= 0 or size % ctypes.sizeof(ctypes.c_int):
                raise OSError(ctypes.get_errno(), 'Cannot enumerate processes')
            if size < ctypes.sizeof(values):
                result = []
                for pid in values[:size // ctypes.sizeof(ctypes.c_int)]:
                    if pid > 0:
                        row = self.info(pid, full=False)
                        if row is not None:
                            result.append(row)
                return result
            capacity *= 2
        raise RuntimeError('Process enumeration exceeded monitoring capacity')


class Memory:
    def __init__(self):
        self.metric = "aggregate-rss"
        self.lib = None
        self.sizes = {}
        self.starts = {}
        self.owned = {}
        self.native = None
        self.failure_context = None
        if sys.platform == "darwin":
            self.native = NativeProcesses()
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
            try:
                # Field 22 is the process birth tick; parentheses may contain spaces.
                fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
                self.starts[pid] = int(fields[19])
            except FileNotFoundError:
                return 0
            return max(rss, int(fields[21]) * os.sysconf('SC_PAGE_SIZE'))
        try:
            identity = self.native.info(pid)
        except OSError:
            self.failure_context = self.native.info(pid, full=False)
            raise
        if identity is None or identity['status'] == 5:  # SDK sys/proc.h: SZOMB.
            return 0
        usage = Usage()
        if self.lib.proc_pid_rusage(pid, 0, ctypes.byref(usage)) != 0:
            code = ctypes.get_errno()
            if code == errno.ESRCH:
                return 0  # Process exited between the process and memory reads.
            terminal = self.native.info(pid)
            if terminal is None or terminal['status'] == 5:
                return 0
            self.failure_context = terminal
            raise OSError(code, "Cannot measure owned process", pid)
        if usage.proc_exit_abstime:
            return 0
        after = self.native.info(pid)
        if after is None or after['status'] == 5:
            return 0
        if after['birth'] != identity['birth']:
            raise RuntimeError('Process identity changed during memory measurement')
        self.starts[pid] = identity['birth']
        return max(rss, usage.resident_size, usage.phys_footprint)

    def tree(self, root):
        # Moon or a browser can place a descendant in another process group.
        # Retain observed ownership across reparenting, with birth-time checks
        # so a recycled PID never grants ownership of an unrelated process.
        rows = {}
        if self.native is not None:
            for row in self.native.snapshot():
                if row['status'] != 5:
                    rows[row['pid']] = (row['parent'], row['group'], 0)
        else:
            output = subprocess.check_output(
                ['ps', '-axo', 'pid=,ppid=,pgid=,rss=,stat='], text=True, timeout=3)
            for line in output.splitlines():
                pid, parent, group, rss, state = line.split()
                if 'Z' not in state:
                    rows[int(pid)] = (int(parent), int(group), int(rss) * 1024)
        sizes = {}
        for pid, (_, _, rss) in rows.items():
            if pid in self.owned:
                size = self.read(pid, rss)
                if size and self.starts[pid] == self.owned[pid]:
                    sizes[pid] = size
        pending = set(rows) - set(sizes)
        while True:
            added = []
            for pid in pending:
                parent, group, rss = rows[pid]
                if group == root or parent in sizes:
                    size = self.read(pid, rss)
                    if size:
                        # Publish ownership immediately: a later unreadable PID
                        # must not prevent cleanup of this verified descendant.
                        self.owned[pid] = self.starts[pid]
                        sizes[pid] = size
                        added.append(pid)
            if not added:
                break
            pending.difference_update(added)
        self.sizes = sizes
        self.owned = {pid: self.starts[pid] for pid in sizes}
        return sum(sizes.values()), list(sizes)

    def stop_tree(self, root):
        stop_group(root)
        errors = []
        for pid, birth in list(self.owned.items()):
            try:
                if self.native is not None:
                    row = self.native.info(pid)
                    alive = row is not None and row['status'] != 5 and row['birth'] == birth
                else:
                    alive = self.read(pid, 0) and self.starts[pid] == birth
                if alive:
                    os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except (OSError, RuntimeError) as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError('; '.join(errors))

def processes():
    if sys.platform == 'darwin':
        return [(row['pid'], row['group'], 0, 'Z' if row['status'] == 5 else 'S',
                 row['uid'], row['comm']) for row in NativeProcesses().snapshot()]
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


def stop_group(pgid):
    # A cutoff must stop allocations immediately, including children ignoring TERM.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-mib", type=int, default=1024)
    parser.add_argument("--process-memory-mib", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument('--phases', type=Path,
                        help='Ordered phase manifest; timeout applies to each phase (at most 120s)')
    parser.add_argument("--lock", type=Path, default=(
        Path.home() / ".cache" / "grounds-build.guard.lock"
    ))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if (not command or args.memory_mib < 1 or not math.isfinite(args.timeout) or args.timeout <= 0
            or (args.process_memory_mib is not None and args.process_memory_mib < 1)):
        parser.error("A command, positive memory cutoff and timeout are required")
    if args.phases is not None and args.timeout > 120:
        parser.error('A declared phase may not exceed the existing 120-second limit')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.lock.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    report = {
        "command": command, "cwd": str(Path.cwd()),
        "memory_limit_bytes": args.memory_mib * MIB,
        "process_memory_limit_bytes": (args.process_memory_mib * MIB
                                       if args.process_memory_mib is not None else None),
        "timeout_seconds": args.timeout, "sample_interval_seconds": SAMPLE_INTERVAL,
        "pressure_interval_seconds": PRESSURE_INTERVAL,
        "peak_bytes": 0, "peak_processes": [], "reason": None,
    }
    job = None
    lock = None
    phases = None
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
        pressure = SystemPressure()
        report["system_pressure_metric"] = pressure.metric
        report["system_pressure"] = pressure.read()
        report["system_pressure_samples"] = 1
        if report["system_pressure"] in ("warning", "critical"):
            report["reason"] = "system-memory-pressure-before-launch"
            return exit_code
        next_pressure_check = time.monotonic() + PRESSURE_INTERVAL
        environment = dict(os.environ, MOON_CONCURRENCY="1", PYTHONDONTWRITEBYTECODE="1")
        if args.phases is not None:
            from check_phase import Phases
            phases = Phases(args.phases, args.timeout, report)
            environment['GROUNDS_CHECK_PHASE_SOCKET'] = phases.address
        job = subprocess.Popen(command, start_new_session=True, env=environment,
                               pass_fds=(lock.fileno(),))
        report["pid"] = job.pid
        while True:
            if received_signal is not None:
                report["reason"] = "signal"
                exit_code = 128 + received_signal
                break
            size, members = memory.tree(job.pid)
            report["samples"] = report.get("samples", 0) + 1
            largest_pid, largest_size = max(memory.sizes.items(),
                                            key=lambda item: item[1], default=(None, 0))
            if largest_size > report.get("max_process_bytes", 0):
                report.update(max_process_bytes=largest_size,
                              max_process_pid=largest_pid)
            if size > report["peak_bytes"]:
                report.update(peak_bytes=size, peak_processes=members,
                              peak_process_memory_bytes=dict(memory.sizes))
            if (report["process_memory_limit_bytes"] is not None
                    and any(value > report["process_memory_limit_bytes"]
                            for value in memory.sizes.values())):
                report["reason"] = "process-memory-cutoff"
                report["violating_process_memory_bytes"] = {
                    pid: value for pid, value in memory.sizes.items()
                    if value > report["process_memory_limit_bytes"]
                }
                exit_code = 137
                break
            if size > report["memory_limit_bytes"]:
                report["reason"] = "memory-cutoff"
                exit_code = 137
                break
            if time.monotonic() >= next_pressure_check:
                report["system_pressure"] = pressure.read()
                report["system_pressure_samples"] += 1
                next_pressure_check = time.monotonic() + PRESSURE_INTERVAL
                if report["system_pressure"] in ("warning", "critical"):
                    report["reason"] = "system-memory-pressure"
                    exit_code = 137
                    break
            now = time.monotonic()
            if (phases.expired(now) if phases is not None else now - start > args.timeout):
                report['reason'] = 'timeout'
                if phases is not None:
                    report['reason'] = 'phase-timeout' if phases.active is not None else 'phase-idle-timeout'
                exit_code = 124
                break
            if phases is not None:
                phases.observe(size)
                phases.poll(now)
            code = job.poll()
            if code is not None:
                _, members = memory.tree(job.pid)
                report["reason"] = "child-exit" if not members else "leftover-children"
                exit_code = (code if code >= 0 else 128 - code) if not members else 125
                if exit_code == 0 and phases is not None:
                    phases.finish()
                break
            time.sleep(SAMPLE_INTERVAL)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(reason="guard-error", error=str(error))
        if job is not None and memory.failure_context is not None:
            report['memory_observation_failure'] = memory.failure_context
        exit_code = 125
    finally:
        if job is not None:
            try:
                memory.stop_tree(job.pid)
            except (OSError, RuntimeError) as error:
                stop_group(job.pid)
                report.update(reason='cleanup-error', error=str(error))
                exit_code = 125
            report["child_exit_code"] = job.wait()
        if phases is not None:
            phases.close()
        if lock is not None:
            lock.close()
        report.update(exit_code=exit_code, elapsed_seconds=round(time.monotonic() - start, 3))
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Build guard: {report['reason']}; peak {report['peak_bytes'] / MIB:.1f} MiB; "
              f"report {args.report}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
