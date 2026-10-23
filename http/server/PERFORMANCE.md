# Native HTTPS performance baseline

This diagnostic compares the opt-in native Bend TLS implementation with the
legacy OpenSSL implementation. It imposes no latency or throughput threshold.
Synthetic test credentials only; these numbers do not qualify live secrets.

`examples/bend_perf_native.bend` and `examples/bend_perf_legacy.bend` import the
same `bend_perf_app.bend` handler, which returns HTTP 200 and `perf ok\n` (eight
body bytes). Their HTTP transport and TLS implementations differ. The server
comparison uses the same Python/OpenSSL peer against each executable. The client
comparison runs the real Bend and legacy client `open` functions and production
one-slot pools against the **same native Bend server process** for each suite.

Each row measures 50 fresh full TLS opens after five warmups, then 200 sequential
GETs after five warmup GETs on a kept connection. Handshake timing includes DNS
resolution and TCP connect, but excludes close, printing, process startup,
initial credential/Unicode asset reads, and compilation. Construction of Unicode
tables and certificate verification inside the production client's `open` are
included. Throughput excludes connection setup,
warmup, and teardown. There is no session cache or resumption. Python asserts
that its socket never changes; the production clients use their one-slot pools,
with server maximum requests raised from 100 to 10,000 to avoid scheduled
connection turnover. This is loopback request throughput at concurrency one,
not a saturation or parallel-load result.

Both TLS 1.3 suites are measured separately: AES-128-GCM-SHA256 (0x1301) and
ChaCha20-Poly1305-SHA256 (0x1303). Both use X25519 key exchange and the same
synthetic ECDSA P-256 leaf and CA. A disposable `OPENSSL_CONF` selects exactly one
suite and X25519; it is loaded only in the peer/legacy subprocesses, without
changing machine settings. The native server independently restricts its suite.
The Python peer asserts TLS version, negotiated suite, ALPN `http/1.1`, full
certificate verification, HTTP status, response body, and socket reuse. Native
clients use their explicit synthetic anchor; legacy clients use `GROUNDS_TLS_CA`.
The production legacy client does not offer ALPN, while the native client offers
`http/1.1`; both use HTTP/1.1. This records the existing implementations rather
than changing either client for the benchmark.

The native executables are built with the existing legacy TLS/cookie abort
overlay. Emitted C, defined C names, and native imports are audited; runtime
`BEND_LIBSSL` and `GROUNDS_TLS_CA` are poisoned in native subprocesses. OpenSSL is
used only by the legacy implementation, fixture generator and independent peer.
No host TLS or crypto is called from the native Bend path.

Reproduce from the repository root (Bend 2.0.38 and OpenSSL 3 first in PATH):

```sh
A="$HOME/.codex/artifacts/grounds/2026-10-23/m4b/round2/perf"
export PYTHONDONTWRITEBYTECODE=1
export BUN_OPTIONS=--smol BUN_JSC_forceRAMSize=134217728
python3 http/server/examples/bend_perf.py --manifest --artifacts "$A"
python3 tools/build_guard.py --memory-mib 4096 --process-memory-mib 4096 \
  --timeout 120 --phases "$A/phases.json" --report "$A/guard-01.json" -- \
  nice -n 10 python3 http/server/examples/bend_perf.py --all --artifacts "$A"
```

Use a new artifact directory for a repeat: native compilation refuses to
overwrite an existing executable. `OPENSSL` can name a specific OpenSSL 3 binary;
discovery checks PATH before portable Homebrew fallback locations. No additional
driver is installed. Eleven declared phases separately bound fixture creation,
each frontend, each native compile, and each suite workload to 120 seconds under
the 4096 MiB aggregate and per-process guard. The benchmark stays outside package
acceptance to avoid making environmental speed a gate.

`metadata.json` records machine, tool versions, fixture/source hashes, command,
and timestamp. Each build and audit has its own report. `baseline.json` includes
all eight rows and raw handshake samples; `results-aes.json` and
`results-chacha.json` retain per-suite measurements. Percentile 50 is the median;
percentile 95 is nearest rank. The server peer uses `perf_counter_ns`; production
client timing uses `IO.now` with millisecond resolution, so short legacy
handshakes are quantized. Results are a single measured run on a shared host;
allocator, scheduler, guard sampling and thermal state can influence them.

## Recorded run

2026-10-23, Mac16,10 / Apple M4, 10 CPUs, 16 GiB RAM, macOS Darwin 25.6.0
(arm64). Bend 2.0.38; Apple Clang 21.0.0; Python 3.13.12 using OpenSSL 3.0.18;
fixture/legacy OpenSSL 3 discovery: `/opt/homebrew/Cellar/openssl@3/3.6.3/bin/openssl`
(3.6.3). No driver installation. All reported handshakes use 50 measured samples.

| Target | Engine | Suite | p50 ms | p95 ms | Keep-alive requests/s |
|---|---|---|---:|---:|---:|
| Server | Bend | AES-128-GCM | 24.855 | 26.801 | 4740.16 |
| Server | Legacy OpenSSL | AES-128-GCM | 0.433 | 0.476 | 12607.89 |
| Client | Bend | AES-128-GCM | 100.000 | 106.000 | 3278.69 |
| Client | Legacy OpenSSL | AES-128-GCM | 23.000 | 25.000 | 5405.41 |
| Server | Bend | ChaCha20-Poly1305 | 23.381 | 25.196 | 7799.83 |
| Server | Legacy OpenSSL | ChaCha20-Poly1305 | 0.461 | 0.516 | 12401.05 |
| Client | Bend | ChaCha20-Poly1305 | 99.000 | 102.000 | 7407.41 |
| Client | Legacy OpenSSL | ChaCha20-Poly1305 | 22.000 | 26.000 | 9090.91 |

Guarded execution passed **11/11 phases**, 102.769 seconds total, peak aggregate
1534.5 MiB. Both native emitted-C/import audits passed. The two workload phases
completed within their individual 120-second limits. The baseline is slower than
legacy OpenSSL for both handshake and request measurements on this host; no
optimization or production-readiness claim follows from these measurements.

Reports are under
`~/.codex/artifacts/grounds/2026-10-23/m4b/round2/perf/`:

- `guard-04.json`: successful complete guarded run.
- `baseline.json`, `results-aes.json`, `results-chacha.json`: eight rows and raw samples.
- `metadata.json`: exact hardware, tool versions, command and input hashes.
- `server-native-audit.json`, `client-native-audit.json`: no-delegation evidence.

Earlier attempts are retained: `guard-01.json` stopped on a metadata command
(`bend --version`, corrected to `bend version`); `guard-02.json` rejected the
generic native server entrypoint because its graph still reached legacy TLS
abort registrations (corrected to the dedicated Bend entrypoint);
`guard-03.json` rejected a multiply consumed Bool in the new client fixture
(corrected to `+observed`). `attempt2/` and `attempt3/` retain their artifacts.
These are harness failures, not pressure stops or failing measured rows. The
successful run used fresh generated binaries and retained the same guard caps,
120-second deadlines, 50-handshake minimum, and response assertions.
