"""Audit an emitted Bend TLS role for host TLS/crypto delegation.

This checks emitted effect constructor IDs and registrations, JS imports and
host crypto calls, native undefined symbols, linked libraries, and literal
OpenSSL dynamic-loader names retained in the executable. It does not grep
unpreprocessed C for arbitrary SSL text: wire's shared effect file deliberately
contains inactive legacy TLS branches. Numeric CID definitions determine which
C effect registrations can be active. JS registrations are executable, so an
unused registered legacy ENOSYS TLS stub is still reported as a failure.

This is a static no-delegation receipt, not proof of physical secret erasure or
constant-time execution. Pair it with interop built by
bend_tls_no_delegation_build.py, which removes legacy TLS/cookie effects.
Invalid BEND_LIBSSL/GROUNDS_TLS_CA paths alone do not disable loader fallbacks.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


REQUIRED = {"wire_random_bytes", "wire_connect_timeout", "wire_recv_timeout", "wire_send_timeout"}
FORBIDDEN_EFFECT = re.compile(
    r"(?:^|[_.:])(?:wire_tls(?:_|$)|openssl(?:_|$)|ssl(?:_|$)|tls(?:_|$)|"
    r"evp(?:_|$)|hmac(?:_|$)|hkdf(?:_|$)|aes(?:_|$)|chacha(?:_|$)|poly1305(?:_|$)|"
    r"sha(?:1|256|384|512)?(?:_|$)|x25519(?:_|$)|ecdsa(?:_|$)|rsa(?:_|$)|x509(?:_|$))", re.I)
FORBIDDEN_SYMBOL = re.compile(
    r"^(?:OPENSSL_|SSL_|TLS_|DTLS_|EVP_|RAND_|HMAC(?:_|$)|CRYPTO_|X509_|BIO_|"
    r"BN_|EC_|ECDH_|ECDSA_|RSA_|DSA_|DH_|AES_|SHA(?:1|224|256|384|512)?(?:_|$)|"
    r"CHACHA|POLY1305|HKDF|PKCS[0-9]*_|PEM_|ERR_|OSSL_|CCCrypt|CCHmac|CC_SHA|"
    r"mbedtls_|gnutls_|wolfSSL_|sodium_)", re.I)
FORBIDDEN_LIBRARY = re.compile(
    r"(?:lib(?:ssl|crypto|boringssl|mbedtls|gnutls|wolfssl|sodium)(?:[./0-9_-]|$)|"
    r"(?:^|[/.:_-])openssl(?:[/.:_-]|$)|^(?:node:)?(?:tls|https|crypto)$|"
    r"Security\.framework|CommonCrypto)", re.I)


def strip_comments(source):
    """Preserve quoted import/ID strings while excluding comment examples."""
    token = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')
    return token.sub(lambda match: "" if match.group().startswith(("//", "/*")) else match.group(), source)


def effect_bad(name):
    # Historical cookie IDs may be qualified by the importing module. Neither
    # TLS role needs a host sign/verify effect, even an unavailable trap.
    return bool(re.search(r"(?:^|[_.:])(?:sign|verify)$", name)) or bool(FORBIDDEN_EFFECT.search(name))


def missing_required(names, required=REQUIRED):
    # Bend qualifies C IDs with module underscores and JS IDs with a colon.
    def normalize(name):
        return name.replace(":", "_").replace(".", "_")
    return sorted(item for item in required if not any(
        normalize(name) == normalize(item) or normalize(name).endswith("_" + normalize(item))
        for name in names))


def c_effects(source, required=REQUIRED):
    clean = strip_comments(source)
    defined = set(re.findall(r"^\s*#\s*define\s+CID_([A-Za-z0-9_]+)\s+[0-9]+\b", clean, re.M))
    candidates = set(re.findall(r"\bio_eff\s*\(\s*CID_([A-Za-z0-9_]+)\s*,", clean))
    candidates.update(re.findall(r"\bio_eff\s*\(\s*CID\s*\(\s*([A-Za-z0-9_.]+)\s*\)\s*,", clean))
    active = {name for name in candidates if name.replace(".", "_") in defined}
    return dict(numeric_cid_count=len(defined), active_effect_ids=sorted(active),
                inactive_registration_ids=sorted(candidates - active),
                forbidden_defined_ids=sorted(name for name in defined if re.search(r"(?:^|_)wire_tls_", name)),
                forbidden_effect_ids=sorted(name for name in active if effect_bad(name)),
                missing_byte_tcp_rng_effects=missing_required(active, required))


def js_effects(source, required=REQUIRED):
    clean = strip_comments(source)
    registered = set(re.findall(r'\bio_eff\s*\(\s*["\']([^"\']+)["\']\s*,', clean))
    unresolved = re.findall(r"\bio_eff\s*\(\s*CID\s*\(", clean)
    # Emitted effects are constructed as {$: "effect-id", args: [...], kont:...}.
    # Also report these separately so unused executable registrations are never
    # confused with constructor paths present in the generated program.
    constructed = set(re.findall(r'\$\s*:\s*["\']([^"\']+)["\']\s*,\s*args\s*:', clean))
    imported = set(re.findall(r'\b(?:require|import)\s*\(\s*["\']([^"\']+)["\']', clean))
    imported.update(re.findall(r'\bfrom\s*["\']([^"\']+)["\']', clean))
    imported.update(re.findall(r'\bimport\s*["\']([^"\']+)["\']', clean))
    libraries = set(re.findall(r'\bdlopen\s*\(\s*["\']([^"\']+)["\']', clean))
    # Conditional literal loader choices (e.g. sys.mac ? libSystem : libc).
    literals = re.findall(r'["\']([^"\'\n]+)["\']', clean)
    loader_expressions = re.findall(r"\bdlopen\s*\(\s*([^,]+)", clean)
    loader_literals = set(libraries)
    for expression in loader_expressions:
        loader_literals.update(re.findall(r"[\"']([^\"'\n]+)[\"']", expression))
    # Bare Crypto/TLS strings also name pure Bend constructors. Module imports
    # and actual dlopen arguments are checked separately above, case-insensitively.
    forbidden_loaders = sorted(value for value in set(literals) if FORBIDDEN_LIBRARY.search(value)
                               and (value.lower() not in {"crypto", "tls", "https"} or value in loader_literals))
    host_calls = sorted(set(re.findall(
        r"\b(?:createCipheriv|createDecipheriv|createHmac|createHash|createSign|createVerify|"
        r"crypto\s*\.\s*subtle\s*\.\s*(?:encrypt|decrypt|deriveBits|deriveKey|sign|verify|digest)|"
        r"(?:tls|https)\s*\.\s*(?:connect|createServer|request))\s*\(", clean)))
    return dict(registered_effect_ids=sorted(registered), constructed_effect_ids=sorted(constructed),
                unresolved_cid_registrations=len(unresolved), imports=sorted(imported),
                literal_dlopen_libraries=sorted(libraries),
                forbidden_effect_ids=sorted(name for name in registered | constructed if effect_bad(name)),
                missing_byte_tcp_rng_effects=missing_required(registered, required),
                forbidden_imports=sorted(name for name in imported if FORBIDDEN_LIBRARY.search(name)),
                forbidden_loader_literals=forbidden_loaders, forbidden_host_crypto_calls=host_calls)


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError(f"{argv!r} failed ({result.returncode}): {result.stderr.strip()}")
    return dict(argv=argv, stdout=result.stdout, stderr=result.stderr)


def c_defined_names(source):
    """File-scope functions and arrays the emitted program defines itself, e.g.
    the Bend runtime's err_fail(...) and ERR_TEXT[]."""
    clean = strip_comments(source)
    return set(re.findall(r"^(?:[A-Za-z_]\w*[ \t*]+)+([A-Za-z_]\w*)[ \t]*[(\[]", clean, re.M))


def dynamic_literals(lines, defined, own_names):
    """Forbidden-looking strings in a binary, less those that are only the symbol
    table entries of names the emitted C itself defines. Static OpenSSL would be
    defined but not in the emitted C, and a dlopen/dlsym literal is not a defined
    symbol, so both stay forbidden."""
    flagged, exempt = set(), set()
    for line in lines:
        value = line.strip()
        if FORBIDDEN_SYMBOL.match(value) or FORBIDDEN_LIBRARY.search(value):
            (exempt if value in defined and value in own_names else flagged).add(value)
    return sorted(flagged), sorted(exempt)


def native_imports(path, own_names=frozenset()):
    nm = shutil.which("nm")
    if not nm:
        raise RuntimeError("nm is required for native import evidence")
    symbols = command([nm, "-u", str(path)])
    imported = set()
    for line in symbols["stdout"].splitlines():
        fields = line.split()
        if fields and not fields[-1].endswith(":"):
            # macOS prefixes external symbols with _, ELF may suffix versions.
            imported.add(fields[-1].lstrip("_").split("@", 1)[0])
    if sys.platform == "darwin":
        loader = shutil.which("otool")
        if not loader:
            raise RuntimeError("otool is required for linked-library evidence on macOS")
        linked = command([loader, "-L", str(path)])
        libraries = [line.strip().split(" (", 1)[0] for line in linked["stdout"].splitlines()[1:] if line.strip()]
    else:
        loader = shutil.which("readelf")
        if not loader:
            raise RuntimeError("readelf is required for linked-library evidence")
        linked = command([loader, "-d", str(path)])
        libraries = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", linked["stdout"])
    strings = shutil.which("strings")
    if not strings:
        raise RuntimeError("strings is required for dynamic-loader name evidence")
    literals = command([strings, "-a", str(path)])
    table = command([nm, str(path)])
    defined = set()
    for line in table["stdout"].splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-2] not in ("U", "u", "w", "v"):
            defined.add(fields[-1].lstrip("_").split("@", 1)[0])
    dynamic, exempt = dynamic_literals(literals["stdout"].splitlines(), defined, own_names)
    return dict(undefined_symbol_command=symbols, imported_symbols=sorted(imported),
                linked_library_command=linked, linked_libraries=libraries,
                strings_command=literals["argv"], forbidden_dynamic_loader_literals=dynamic,
                exempt_own_program_literals=exempt,
                forbidden_imported_symbols=sorted(name for name in imported if FORBIDDEN_SYMBOL.match(name)),
                forbidden_linked_libraries=sorted(name for name in libraries if FORBIDDEN_LIBRARY.search(name)))


def self_check():
    c = "\n".join(f"#define CID_wire_{name} {n}\nio_eff(CID_wire_{name}, os_effect);" for n,name in enumerate(sorted(REQUIRED),1))
    assert not c_effects(c)["missing_byte_tcp_rng_effects"]
    assert c_effects(c + "\n#define CID_wire_wire_tls_connect 999\nio_eff(CID_wire_wire_tls_connect, legacy);")["forbidden_effect_ids"]
    assert c_effects(c + "\n#define CID_http_core_cookie_sign_sign 999\nio_eff(CID_http_core_cookie_sign_sign, legacy);")["forbidden_effect_ids"]
    js = "\n".join(f'io_eff("wire:{name}", os_effect);' for name in REQUIRED)
    assert not js_effects(js)["missing_byte_tcp_rng_effects"]
    assert not js_effects(js + 'const pure = {$:"Crypto"};')["forbidden_loader_literals"]
    assert js_effects(js + 'io_eff("wire:wire_tls_connect", legacy);')["forbidden_effect_ids"]
    assert js_effects(js + 'io_eff("http.core.cookie_sign:sign", legacy);')["forbidden_effect_ids"]
    assert js_effects(js + 'require("node:crypto");')["forbidden_imports"]
    assert js_effects(js + 'ffi.dlopen(mac ? "libssl.dylib" : "libcrypto.so", {});')["forbidden_loader_literals"]
    assert js_effects(js + 'ffi.dlopen("Crypto", {});')["forbidden_loader_literals"]
    assert c_effects("")["missing_byte_tcp_rng_effects"]
    own = c_defined_names('static const char* ERR_TEXT[] = { "" };\nFAR int err_claim(void) {\n  return err_fail(x);\n}')
    assert own == {"ERR_TEXT", "err_claim"}, own
    lines = ["err_claim", "ERR_TEXT", "EVP_EncryptInit", "SSL_read", "libssl.so.3"]
    flagged, exempt = dynamic_literals(lines, {"err_claim", "ERR_TEXT", "EVP_EncryptInit"}, own)
    assert exempt == ["ERR_TEXT", "err_claim"], exempt
    assert flagged == ["EVP_EncryptInit", "SSL_read", "libssl.so.3"], flagged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--js", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--role", choices=["client", "server"], default="client")
    args = parser.parse_args()
    self_check()
    report = dict(scope="Static emitted-program/import audit; pair with independent live synthetic interop",
                  limits="Does not prove physical erasure, constant-time execution, or arbitrary-code absence",
                  c_analysis="Actual numeric CID definitions select registrations; dormant shared C is permitted",
                  invalid_loader_environment_for_interop={"BEND_LIBSSL": "/nonexistent/grounds-test-libssl",
                      "GROUNDS_TLS_CA": "/nonexistent/grounds-test-host-ca"}, results={})
    problems = []
    for name in ("native", "c", "js"):
        path = getattr(args, name)
        if not path.is_file():
            problems.append(f"{name}: missing artifact {path}")
        else:
            report[name + "_artifact"] = dict(path=str(path.resolve()), bytes=path.stat().st_size,
                                              sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    if not problems:
        required = REQUIRED if args.role == "client" else {"wire_random_bytes", "wire_recv_timeout", "wire_send_timeout", "TCP.listen", "TCP.accept"}
        report["role"] = args.role
        report["results"]["c"] = c_effects(args.c.read_text(), required)
        report["results"]["js"] = js_effects(args.js.read_text(), required)
        try:
            report["results"]["native"] = native_imports(args.native, c_defined_names(args.c.read_text()))
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            problems.append(f"native evidence unavailable: {error}")
        for target, result in report["results"].items():
            for name, findings in result.items():
                if (name.startswith("forbidden_") or name.startswith("missing_") or name == "unresolved_cid_registrations") and findings:
                    problems.append(f"{target} {name}: {findings}")
    report.update(passed=not problems, problems=problems)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(dict(passed=not problems, problems=problems), sort_keys=True))
    if problems:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
