"""Record local RNG, byte-build/scan and retained UDP baselines; no speed gates.

python3 measure.py <evidence-dir> <native-bench> <bun-bench.js> <native-udp> <bun-udp.js>
The executables must have been built from the recorded source. Synthetic local
fixtures only. Startup is excluded from Bend's ms counter, included in peak RSS.
"""
import hashlib
import errno
import json
import pathlib
import platform
import random
import re
import select
import socket
import statistics
import subprocess
import sys
import time


def measured(command):
    run = subprocess.run(["/usr/bin/time", "-l", *command], text=True, capture_output=True, check=True, timeout=120)
    result = json.loads(run.stdout)
    peak = re.search(r"(\d+)\s+maximum resident set size", run.stderr)
    assert peak and isinstance(result["ms"], int) and result["ms"] >= 0
    return {**result, "peak_rss_bytes": int(peak[1]), "command": command}


def udp(command, size, repetitions):
    process = subprocess.Popen([*command, "127.0.0.1", "0", "0", str(repetitions)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([process.stdout], [], [], 10)[0], "UDP readiness timeout"
        ready = process.stdout.readline().strip()
        assert ready.startswith("bound:127.0.0.1:"), ready
        port = int(ready.rsplit(":", 1)[1])
        assert process.stdout.readline().strip() == "rejections:0"
        payload = bytes(i & 255 for i in range(size))
        rejected = None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(5)
            started = time.perf_counter_ns()
            for _ in range(repetitions):
                try:
                    assert peer.sendto(payload, ("127.0.0.1", port)) == size
                except OSError as error:
                    if error.errno != errno.EMSGSIZE: raise
                    rejected = error.errno
                    break
                echoed, source = peer.recvfrom(65535)
                assert echoed == payload and source == ("127.0.0.1", port)
            elapsed = time.perf_counter_ns() - started
        stdout, stderr = process.communicate(timeout=10)
        if rejected is None:
            assert process.returncode == 0 and stdout.strip() == "closed", (stdout, stderr)
        else:
            # The fixture times out its actual receive and closes its socket;
            # no forced process termination counts as cleanup evidence.
            assert process.returncode == 3 and "UDP echo receive failed" in stderr, (stdout, stderr)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as check:
            check.bind(("127.0.0.1", port))
        if rejected is not None:
            return {"rejected": True, "errno": rejected, "reason": "peer sendto exceeds this host's default UDP limit",
                    "fixture_exit": process.returncode, "command": command, "port_rebound": True}
        return {"ns": elapsed, "mib_s_both_directions": size * repetitions * 2 / 1048576 / (elapsed / 1e9), "command": command, "port_rebound": True}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def main():
    assert platform.system() == "Darwin", "This runner's time -l RSS units are verified on macOS only"
    out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
    native, js, native_udp, js_udp = sys.argv[2:]
    programs = {"native": [native], "bun": ["bun", js]}
    udp_programs = {"native": [native_udp], "bun": ["bun", js_udp]}
    configs = [(target, mode, size, reps) for target in programs for mode in ("bulk", "word")
               for size, reps in ((16, 1000), (4096, 100), (65536, 10), (1048576, 1))]
    configs += [(target, mode, size, reps) for target in programs for mode in ("list", "bytes", "array")
                for size, reps in ((4096, 1000), (65536, 100), (1048576, 8))]
    order = [(config, attempt) for config in configs for attempt in range(3)]
    random.Random(47).shuffle(order)
    results = {"scope": "macOS local public/synthetic baseline; no entropy/timing safety or capacity claim",
               "timer": "Bend monotonic milliseconds; zero is below counter resolution", "samples": [], "udp": []}
    results["macos_udp_maxdgram"] = int(subprocess.check_output(["sysctl", "-n", "net.inet.udp.maxdgram"], text=True))
    source = pathlib.Path(__file__).resolve().parent
    inputs = [*source.glob("*.bend"), *source.glob("effs/*"), pathlib.Path(__file__).resolve()]
    results["source_sha256"] = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs if p.is_file()}
    for (target, mode, size, reps), attempt in order:
        sample = measured([*programs[target], mode, str(size), str(reps)])
        if mode not in ("bulk", "word"):
            expected = (size // 256 * 32640 + sum(range(size % 256))) * reps & 0xffffffff
            assert sample["checksum"] == expected, (target, mode, size, sample)
        sample.update(target=target, mode=mode, size=size, repetitions=reps, attempt=attempt)
        results["samples"].append(sample)
        (out / "measurements.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"{target} {mode} {size} x {reps}: {sample['ms']}ms, peak RSS {sample['peak_rss_bytes']} bytes", flush=True)
    for target in udp_programs:
        for size in (256, 1200, 8192, 16384):
            for attempt in range(3):
                value = udp(udp_programs[target], size, 200)
                value.update(target=target, size=size, repetitions=200, attempt=attempt)
                results["udp"].append(value)
                (out / "measurements.json").write_text(json.dumps(results, indent=2) + "\n")
                if value.get("rejected"):
                    print(f"{target} UDP {size}: peer EMSGSIZE recorded; fixture closed by receive deadline, port rebound", flush=True)
                else:
                    print(f"{target} UDP {size}: {value['mib_s_both_directions']:.2f} MiB/s aggregate echo, actual bytes verified, port rebound", flush=True)
    summary = []
    for target, mode, size, reps in configs:
        samples = [s for s in results["samples"] if (s["target"], s["mode"], s["size"]) == (target, mode, size)]
        elapsed = statistics.median(s["ms"] for s in samples)
        summary.append({"target": target, "mode": mode, "size": size, "repetitions": reps, "median_ms": elapsed,
                        "range_ms": [min(s["ms"] for s in samples), max(s["ms"] for s in samples)],
                        "mib_s": size * reps / 1048576 / (elapsed / 1000) if elapsed else None,
                        "median_peak_rss_bytes": statistics.median(s["peak_rss_bytes"] for s in samples)})
    results["summary"] = summary
    results["completed"] = True
    (out / "measurements.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Foundation baseline complete: three samples per workload; no performance threshold or secret-safety claim", flush=True)


if __name__ == "__main__":
    main()
