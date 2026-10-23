"""Compile TLS evaluators with legacy TLS/cookie host effects replaced by aborts.

The disposable overlay preserves every Bend source byte and OS byte/RNG effect.
Only the OpenSSL host implementation and legacy JS stubs are replaced. Run the
ordinary interop corpus against these exact outputs and audit their imports.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TLS = ["wire_tls_connect", "wire_tls_send_timeout", "wire_tls_recv_timeout",
       "wire_tls_close", "wire_tls_listen_ctx", "wire_tls_accept"]


def c_stubs(names):
    return "\n".join(f"""
#ifdef CID({name})
static Term grounds_forbidden_{name}(Env e, Term* f, IoWork* w) {{
  fputs("GROUNDS_FORBIDDEN_HOST_EFFECT:{name}\\n", stderr);
  fflush(stderr);
  _Exit(86);
}}
static void __attribute__((constructor)) grounds_forbidden_{name}_use(void) {{
  io_eff(CID({name}), grounds_forbidden_{name});
}}
#endif
""" for name in names)


def js_stubs(names):
    return "\n".join(f'io_eff(CID({name}), () => {{ throw new Error("GROUNDS_FORBIDDEN_HOST_EFFECT:{name}"); }});'
                     for name in names) + "\n"


def overlay(destination):
    inputs = {}
    # Include cookie compatibility sources so a future accidental import also
    # fails loudly. Exclude bounty, VCS, build output, and unrelated packages.
    for directory in ("wire", "crypto", "io", "utf8", "http/core"):
        for path in sorted((ROOT / directory).rglob("*")):
            if path.is_file() and path.suffix in {".bend", ".c", ".js"}:
                relative = path.relative_to(ROOT)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())
                inputs[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    wire = destination / "wire/effs/wire.c"
    source = wire.read_text()
    start, end = source.index("// TLS\n// ==="), source.index("#ifdef CID(wire_close)")
    wire.write_text(source[:start] + c_stubs(TLS) + "\n" + source[end:])
    (destination / "wire/effs/tls_compat.js").write_text(js_stubs(TLS))
    (destination / "http/core/effs/cookie.c").write_text(c_stubs(["sign", "verify"]))
    (destination / "http/core/effs/cookie.js").write_text(js_stubs(["sign", "verify"]))
    return inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", choices=["client", "server", "legacy-probe", "cookie-probe"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    assert args.output.suffix in {".c", ".js"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="grounds-host-effects-unavailable-") as td:
        temporary = Path(td)
        inputs = overlay(temporary)
        if args.program == "legacy-probe":
            source = temporary / "wire/forbidden_probe.bend"
            source.write_text('import Base\nimport ./wire.bend as W\ndef main() -> IO(Unit):\n  IO.try(Unit,W.wire_tls_listen_ctx("unused","unused"))\n')
        elif args.program == "cookie-probe":
            source = temporary / "http/core/forbidden_probe.bend"
            # Import the real declarations: Bend resolves both CID names even
            # though only sign is reachable in this positive-control program.
            source.write_text('import Base\nimport ./cookie_sign.bend as Cookie\ndef main() -> IO(Unit):\n  IO.bind(String,Unit,IO.try(String,Cookie.sign("synthetic","probe")),IO.print)\n')
        else:
            source = temporary / f"wire/bend_tls_{args.program}_cli.bend"
        command = ["bend", str(source), "-o", str(args.output.resolve())]
        result = subprocess.run(command, text=True, capture_output=True)
        report = dict(command=command, program=args.program, exit=result.returncode,
                      stdout=result.stdout, stderr=result.stderr, input_sha256=inputs,
                      replaced_effects=TLS + ["sign", "verify"],
                      os_byte_rng_effects_unchanged=True, bend_sources_unchanged=True)
        if args.output.exists():
            report["output_sha256"] = hashlib.sha256(args.output.read_bytes()).hexdigest()
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        if result.returncode:
            print(result.stdout, result.stderr)
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
