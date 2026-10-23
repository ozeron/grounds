"""Independent peers for synthetic Bend TLS servers; all TLS under test is Bend.

OpenSSL/Python/Go are peers only. The record proxy observes the peer key log and
can authenticate a deliberately altered client Finished without replacing any
Bend operation. Ordinary negotiation failures are driven as raw wire messages.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from bend_tls_client_check import (fixture, free_port, record, frame, handshake,
                                   Epoch, SUITES, GROUPS, HRR, CIVIL_OFFSET)
from tls_server_handshake_check import hello, cases as negotiation_cases
from tls_server_peer_proxy import ServerProxy
from tls_server_offer_oracle import ignored_offer

ROOT = Path(__file__).resolve().parent
POISON = dict(BEND_LIBSSL="/nonexistent/grounds-m3b-libssl",
              GROUNDS_TLS_CA="/nonexistent/grounds-m3b-host-ca")


def line(process, timeout=8):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise TimeoutError("Bend evaluator did not produce a line")
    return process.stdout.readline().decode().rstrip()


@contextmanager
def server(binary, directory, case, count=1):
    port = free_port()
    command = binary + [str(directory / (case.get("signature", "ecdsa") + ".pem")),
                        str(directory / (case.get("signature", "ecdsa") + ".key")),
                        str(port), str(GROUPS[case.get("group", "x25519")][0]),
                        str(SUITES[case.get("suite", "aes")][0]),
                        case.get("mode", "normal"), str(count)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=dict(os.environ, **POISON), bufsize=0)
    try:
        ready = line(process)
        if ready != "ready":
            raise AssertionError((ready, process.stderr.read().decode()))
        yield port, process, command
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(2)
        process.stdout.close()
        process.stderr.close()


def python_case(binary, directory, case):
    with server(binary, directory, case) as (port, process, command):
        context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as peer:
                peer.sendall(b"ping")
                data = bytearray()
                while len(data) < 4:
                    data.extend(peer.recv(4 - len(data)))
                observed = dict(peer="Python ssl", verification=True, version=peer.version(),
                                cipher=peer.cipher()[0], alpn=peer.selected_alpn_protocol(),
                                application=bytes(data).hex())
                # unwrap requires Bend's authenticated close_notify.
                peer.unwrap().close()
        output, errors = process.communicate(timeout=10)
        observed.update(command=command, stdout=output.decode(), stderr=errors.decode(),
                        returncode=process.returncode)
        observed["passed"] = (data == b"ping" and observed["alpn"] == "http/1.1"
                              and "accepted:" in observed["stdout"] and process.returncode == 0)
        return observed


def openssl_case(binary, directory, openssl, case):
    with server(binary, directory, case) as (port, process, command):
        peer_command = [openssl, "s_client", "-tls1_3", "-quiet", "-connect", f"127.0.0.1:{port}",
                        "-servername", "localhost", "-verify_hostname", "localhost", "-verify_return_error",
                        "-CAfile", str(directory / "ca.pem"), "-alpn", "http/1.1",
                        "-ciphersuites", SUITES[case["suite"]][1], "-groups", GROUPS[case["group"]][1]]
        result = subprocess.run(peer_command, input=b"ping", capture_output=True, timeout=20)
        output, errors = process.communicate(timeout=10)
        expected = f"accepted:{SUITES[case['suite']][0]}:{GROUPS[case['group']][0]}:true:6c6f63616c686f7374"
        return dict(command=command, peer_command=peer_command, stdout=output.decode(), stderr=errors.decode(),
                    peer_stdout=result.stdout.decode(errors="replace"), peer_stderr=result.stderr.decode(errors="replace"),
                    peer_exit=result.returncode, returncode=process.returncode,
                    passed=result.returncode == 0 and result.stdout == b"ping" and expected in output.decode()
                    and process.returncode == 0)


def proxy_case(binary, directory, openssl, case):
    with server(binary, directory, case) as (port, process, command):
        upstream = socket.create_connection(("127.0.0.1",port),timeout=15)
        listener = socket.socket()
        listener.bind(("127.0.0.1",0))
        listener.listen(1)
        keylog = directory / (case["name"]+".keys")
        proxy = ServerProxy(listener,upstream,keylog,case)
        worker = threading.Thread(target=proxy.serve,daemon=True)
        worker.start()
        groups = case.get("peer_groups",GROUPS[case.get("group","x25519")][1])
        peer_command = [openssl,"s_client","-tls1_3","-quiet","-connect",f"127.0.0.1:{listener.getsockname()[1]}",
                        "-servername","localhost","-verify_hostname","localhost","-verify_return_error",
                        "-CAfile",str(directory/"ca.pem"),"-keylogfile",str(keylog),
                        "-ciphersuites","TLS_AES_128_GCM_SHA256","-groups",groups]
        if case["name"] != "absent-alpn":
            peer_command += ["-alpn","http/1.1"]
        if case["name"] == "ignored-psk":
            peer_command += ["-psk", "01"*32, "-psk_identity", "synthetic-unused-psk"]
        payload = b"p"*40000 if case.get("mode") == "bulk" else b"ping"
        try:
            if case.get("mode") == "update":
                peer_process = subprocess.Popen(peer_command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    until=time.monotonic()+10
                    while not any(e.get("keyupdate")==[1] and e["direction"]=="server" for e in proxy.events):
                        if peer_process.poll() is not None or time.monotonic()>until:
                            raise TimeoutError("server KeyUpdate did not arrive")
                        time.sleep(0.01)
                    time.sleep(0.05)
                    stdout,stderr=peer_process.communicate(input=payload,timeout=15)
                    result=subprocess.CompletedProcess(peer_command,peer_process.returncode,stdout,stderr)
                finally:
                    if peer_process.poll() is None:
                        peer_process.terminate()
                        peer_process.communicate(timeout=3)
            else:
                result = subprocess.run(peer_command,input=payload,capture_output=True,timeout=25)
            output,errors = process.communicate(timeout=10)
            worker.join(2)
            alerts = [event["alert"] for event in proxy.events if event.get("direction")=="server" and "alert" in event]
            if "alert" in case:
                passed = [2,case["alert"]] in alerts and f"error:{case['alert']}:" in output.decode() and proxy.mutation_applied
            else:
                alpn = "false" if case["name"] == "absent-alpn" else "true"
                expected = f"accepted:4865:{GROUPS[case.get('group','x25519')][0]}:{alpn}:6c6f63616c686f7374"
                passed = result.returncode == 0 and result.stdout == payload and expected in output.decode() and [1,0] in alerts
                if case["name"].startswith("hrr-"):
                    passed = passed and proxy.hrr_count == 1 and proxy.client_hellos == 2
                if case["name"] == "client-keyupdate":
                    passed = passed and proxy.injected_update and any(e.get("keyupdate")==[0] and e["direction"]=="server" for e in proxy.events)
                if case.get("mode") == "update":
                    passed = passed and any(e.get("keyupdate")==[1] and e["direction"]=="server" for e in proxy.events) and any(e.get("keyupdate")==[0] and e["direction"]=="client" for e in proxy.events)
            return dict(command=command,peer_command=peer_command,stdout=output.decode(),stderr=errors.decode(),
                        peer_stdout_hex=result.stdout.hex(),peer_stderr=result.stderr.decode(errors="replace"),
                        peer_exit=result.returncode,events=proxy.events,proxy_errors=proxy.errors,
                        hrr_count=proxy.hrr_count,client_hellos=proxy.client_hellos,mutation_applied=proxy.mutation_applied,
                        passed=passed and not proxy.errors and process.returncode == 0)
        finally:
            proxy.close()
            worker.join(2)


def lifecycle_case(binary,directory,case):
    with server(binary,directory,case) as (port,process,command):
        with socket.create_connection(("127.0.0.1",port),timeout=5) as peer:
            peer.settimeout(10)
            name=case["name"]
            if name == "disconnect-mid-handshake":
                peer.sendall(b"\x16\x03\x03\x00\x40\x01\x00")
                peer.shutdown(socket.SHUT_WR)
            elif name == "eof":
                peer.shutdown(socket.SHUT_WR)
            # An expired deadline cannot transmit an alert within that deadline.
            response=record(peer)
        output,errors=process.communicate(timeout=10)
        alert=list(response[5:]) if response and response[0]==21 else None
        expected=80 if name=="deadline" else 50
        return dict(command=command,stdout=output.decode(),stderr=errors.decode(),peer_observed_alert=alert,
                    passed=process.returncode==0 and f"error:{expected}:" in output.decode()
                    and (alert==[2,expected] if expected!=80 else response is None))


def descriptor_count(pid, sockets=False):
    proc=Path(f"/proc/{pid}/fd")
    if proc.is_dir():
        paths=list(proc.iterdir())
        return sum(p.readlink().as_posix().startswith("socket:") for p in paths) if sockets else len(paths)
    lsof=shutil.which("lsof") or "/usr/sbin/lsof"
    command=[lsof,"-a","-p",str(pid)] + (["-iTCP"] if sockets else []) + ["-F","f"]
    output=subprocess.check_output(command,text=True)
    return sum(line.startswith("f") for line in output.splitlines())


def cleanup_case(binary,directory,case):
    # One retained listener/process: failed accept owners cannot hide behind
    # per-case process exit. Sample both all descriptors and TCP descriptors.
    deadlines=case["name"]=="deadline-resource-cleanup"
    count=5 if deadlines else 13
    with server(binary,directory,dict(case,mode="timeout" if deadlines else "normal"),count=count) as (port,process,command):
        baseline=dict(fds=descriptor_count(process.pid),tcp=descriptor_count(process.pid,True))
        samples=[]
        for index in range(count):
            kind=3 if deadlines else index%3
            expected=(70,10,50,80)[kind]
            with socket.create_connection(("127.0.0.1",port),timeout=5) as peer:
                peer.settimeout(5)
                if kind==0:
                    peer.sendall(frame(22,hello({43:None})))
                elif kind==1:
                    peer.sendall(frame(20,b"\x01"))
                elif kind==2:
                    peer.sendall(b"\x16\x03\x03\x00\x40\x01")
                    peer.shutdown(socket.SHUT_WR)
                response=record(peer)
            result,handled=line(process),line(process)
            sample=dict(index=index,expected_alert=expected,stdout=[result,handled],
                        peer_alert=list(response[5:]) if response else None)
            sample["passed"]=result.startswith(f"error:{expected}:") and handled=="handled"
            sample["passed"] &= (sample["peer_alert"]==[2,expected] if expected!=80 else response is None)
            if index<count-1:
                sample.update(fds=descriptor_count(process.pid),tcp=descriptor_count(process.pid,True))
                sample["passed"] &= sample["fds"]==baseline["fds"] and sample["tcp"]==baseline["tcp"]
            samples.append(sample)
        output,errors=process.communicate(timeout=5)
    with socket.socket() as rebound:
        rebound.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        rebound.bind(("127.0.0.1",port))
    return dict(command=command,baseline=baseline,samples=samples,listener_rebound=True,
                stdout=output.decode(),stderr=errors.decode(),
                passed=process.returncode==0 and all(s["passed"] for s in samples))


def ignored_offer_case(binary,directory,case):
    with server(binary,directory,case) as (port,process,command):
        with socket.create_connection(("127.0.0.1",port),timeout=10) as peer:
            peer.settimeout(10)
            evidence=ignored_offer(peer)
        output,errors=process.communicate(timeout=5)
        return dict(command=command,evidence=evidence,stdout=output.decode(),stderr=errors.decode(),
                    passed=process.returncode==0 and "accepted:4865:29:true:" in output.decode())


def raw_case(binary, directory, case):
    with server(binary, directory, case) as (port, process, command):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as peer:
            peer.settimeout(10)
            peer.sendall(case["wire"])
            response = record(peer)
        output, errors = process.communicate(timeout=10)
        alert = list(response[5:]) if response and response[0] == 21 else None
        return dict(command=command, wire_sha256=hashlib.sha256(case["wire"]).hexdigest(),
                    response_hex=response.hex() if response else None, peer_observed_alert=alert,
                    stdout=output.decode(), stderr=errors.decode(), returncode=process.returncode,
                    passed=alert == [2, case["alert"]] and f"error:{case['alert']}:" in output.decode()
                    and process.returncode == 0)


def cases():
    rows = []
    for suite in SUITES:
        for group in GROUPS:
            for signature in ("ecdsa", "rsa"):
                rows.append(dict(name=f"openssl-{suite}-{group}-{signature}", peer="openssl", suite=suite,
                                 group=group, signature=signature))
    for signature in ("ecdsa", "rsa"):
        rows.append(dict(name=f"python-{signature}", peer="python", signature=signature))
    for name, raw, expected in negotiation_cases():
        if expected.startswith("error:"):
            rows.append(dict(name="raw-" + name, peer="raw", wire=frame(22,raw), alert=int(expected[6:])))
    rows += [dict(name="invalid-x25519", peer="raw", wire=frame(22,hello(share=b"\x00\x1d\x00\x20" + bytes(32))), alert=47),
             dict(name="invalid-p256", peer="raw", group="p256", wire=frame(22,hello(share=b"\x00\x17\x00\x41\x04" + bytes(64))), alert=47),
             dict(name="ccs-before-ch", peer="raw", wire=frame(20,b"\x01"), alert=10),
             dict(name="invalid-ccs", peer="raw", wire=frame(20,b"\x02"), alert=10)]
    rows += [dict(name=name,peer="proxy",suite="aes",**options) for name,options in [
        ("hrr-p256",dict(group="p256",peer_groups="X25519:P-256")),
        ("hrr-x25519",dict(group="x25519",peer_groups="P-256:X25519")),
        ("fragmented",{}),("coalesced",{}),("absent-alpn",{}),("ignored-psk",{}),
        ("client-keyupdate",{}),("server-keyupdate",dict(mode="update")),
        ("bulk",dict(mode="bulk")),
        ("altered-client-finished",dict(alert=51)),
        ("modified-client-record",dict(alert=20)),
        ("finished-coalesced-message",dict(alert=10)),
        ("finished-partial-tail",dict(alert=10)),
        ("late-client-ccs",dict(alert=10)),
        ("malformed-client-keyupdate",dict(alert=47)),
        ("client-session-ticket",dict(alert=10)),
        ("client-post-handshake-auth",dict(alert=10)),
        ("coalesced-keyupdates",dict(alert=10)),
        ("altered-retry-cookie",dict(group="p256",peer_groups="X25519:P-256",alert=47)),
        ("altered-retry-random",dict(group="p256",peer_groups="X25519:P-256",alert=47)),
    ]]
    rows += [dict(name="disconnect-mid-handshake",peer="lifecycle"),dict(name="eof",peer="lifecycle"),
             dict(name="deadline",peer="lifecycle",mode="timeout")]
    rows += [dict(name="failure-resource-cleanup",peer="cleanup"),dict(name="deadline-resource-cleanup",peer="cleanup")]
    rows += [dict(name="ignored-psk-and-early-data",peer="offer-oracle")]
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--batch-index", type=int)
    parser.add_argument("--expected-batches", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.command[1:] if args.command[:1] == ["--"] else args.command
    openssl = os.environ.get("OPENSSL") or ("/opt/homebrew/opt/openssl@3/bin/openssl"
        if Path("/opt/homebrew/opt/openssl@3/bin/openssl").is_file() else "openssl")
    selected = cases()
    if args.expected_batches is not None:
        assert args.expected_batches == (len(selected)+1)//2, "phase/corpus batch count drift"
    if args.case:
        selected = [case for case in selected if case["name"] in args.case]
    if args.batch_index is not None:
        selected = selected[args.batch_index * 2:args.batch_index * 2 + 2]
    assert selected, "empty case selection"
    results = []
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="grounds-tls-server-") as td:
        directory = Path(td)
        fixtures = fixture(directory, openssl)
        for case in selected:
            started = time.monotonic()
            try:
                if case["peer"] == "python":
                    observed = python_case(binary, directory, case)
                elif case["peer"] == "openssl":
                    observed = openssl_case(binary, directory, openssl, case)
                elif case["peer"] == "proxy":
                    observed = proxy_case(binary,directory,openssl,case)
                elif case["peer"] == "lifecycle":
                    observed = lifecycle_case(binary,directory,case)
                elif case["peer"] == "cleanup":
                    observed = cleanup_case(binary,directory,case)
                elif case["peer"] == "offer-oracle":
                    observed = ignored_offer_case(binary,directory,case)
                else:
                    observed = raw_case(binary, directory, case)
            except Exception as error:
                observed = dict(passed=False, error=repr(error))
            observed.update(case={k:v for k,v in case.items() if k != "wire"}, elapsed=time.monotonic()-started)
            results.append(observed)
            print(case["name"], observed["passed"], flush=True)
    report = dict(passed=all(r["passed"] for r in results), results=results,
                  fixture_sha256=fixtures, environment=POISON,
                  openssl_version=subprocess.check_output([openssl,"version"],text=True).strip(),
                  python_ssl_version=ssl.OPENSSL_VERSION)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
