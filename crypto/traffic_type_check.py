"""The compiler must reject traffic-owner copies and direction mix-ups."""

from pathlib import Path
import os
import subprocess
import tempfile


def main():
    module = Path(__file__).resolve().with_name("traffic.bend")
    with tempfile.TemporaryDirectory() as folder:
        prefix = f"import Base\nimport ./{os.path.relpath(module, Path(folder).resolve())} as T\n\n"
        probes = {
            "copy-write": "def misuse(+owner: T.WriteKey) -> T.WriteKey & T.WriteKey:\n  (owner, owner)\n",
            "copy-read": "def misuse(+owner: T.ReadKey) -> T.ReadKey & T.ReadKey:\n  (owner, owner)\n",
            "wrong-direction": "def misuse(owner: T.ReadKey) -> T.WriteKey:\n  T.close_write(owner)\n",
        }
        for name, body in probes.items():
            path = Path(folder) / f"{name}.bend"
            path.write_text(prefix + body)
            result = subprocess.run(["bend", str(path), "--check-only"], capture_output=True, text=True, timeout=20)
            diagnostic = result.stdout + result.stderr
            assert result.returncode != 0, (name, "invalid owner use compiled")
            assert "Location: misuse" in diagnostic, (name, "unrelated compilation failure", diagnostic)
            if name == "wrong-direction":
                assert any("expected :" in line and line.endswith(".WriteKey") for line in diagnostic.splitlines()), diagnostic
                assert any("observed :" in line and line.endswith(".ReadKey") for line in diagnostic.splitlines()), diagnostic
            else:
                assert "Type" in diagnostic and "Data" in diagnostic, diagnostic
    print("TLS traffic ownership: compiler rejected both affine copies and direction confusion")


if __name__ == "__main__":
    main()
