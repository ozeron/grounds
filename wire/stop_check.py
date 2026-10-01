"""Real signals while Bend's native/Bun accept loop is parked in OS select."""
import signal
import os
import pathlib
import socket
import subprocess
import sys
import time


def main():
    for sig in (signal.SIGTERM, signal.SIGINT):
        for with_connection in (False, True):
            process = subprocess.Popen(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                # read readiness with a deadline, including bridge initialization
                import select
                assert select.select([process.stdout], [], [], 15)[0], "stop fixture readiness deadline"
                assert process.stdout.readline().strip() == "ready, live 1"
                if with_connection:
                    with socket.create_connection(("127.0.0.1", 7201), timeout=2):
                        pass
                    time.sleep(0.15)
                started = time.monotonic()
                process.send_signal(sig)
                stdout, stderr = process.communicate(timeout=3)
                elapsed = time.monotonic() - started
                assert process.returncode == 0, (sig, process.returncode, stdout, stderr)
                assert stdout.strip() == f"stopped: {int(with_connection)} accepted, live 1", (sig, stdout, stderr)
                with socket.socket() as listener:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(("127.0.0.1", 7201))
                print(f"{sig.name}: graceful stop in {elapsed:.3f}s, parked accept, connections={int(with_connection)}, listener released")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
    print("Signal stop: four native/Bun OS delivery and listener cleanup scenarios passed")
    if pathlib.Path(sys.argv[1]).name == "bun":
        # A failed bridge must not silently claim signal handling or leave its
        # temporary C/library files behind. CC is an executable, not shell text.
        import tempfile
        before = set(pathlib.Path(tempfile.gettempdir()).glob("grounds-wire-signal-*"))
        env = {**os.environ, "CC": "/usr/bin/false"}
        failed = subprocess.run(sys.argv[1:], env=env, capture_output=True, text=True, timeout=15)
        assert failed.returncode != 0 and "ready, live" not in failed.stdout
        assert "C signal bridge build failed" in failed.stderr
        after = set(pathlib.Path(tempfile.gettempdir()).glob("grounds-wire-signal-*"))
        assert after == before, "failed signal bridge left build files"
        print("Bun signal bridge: compiler failure is explicit, no ready listener, temporary build files removed")


if __name__ == "__main__":
    main()
