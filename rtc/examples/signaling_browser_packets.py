"""Independently authenticate captured Chrome/Grounds STUN traffic."""
import json
import pathlib
import sys

from stun_reference import COOKIE, attributes, validate


def credentials(sdp):
    return {row.split(":", 1)[0]: row.split(":", 1)[1] for row in sdp.splitlines() if ":" in row}


def main():
    root = pathlib.Path(sys.argv[1])
    result = json.loads((root / "browser.json").read_text())
    assert result["passed"] and len(result["rounds"]) == 2
    rounds = result["rounds"]
    local = [credentials(row["answer"]) for row in rounds]
    remote = [credentials(row["offer"]) for row in rounds]
    for key in ("a=ice-ufrag", "a=ice-pwd"):
        assert local[0][key] != local[1][key] and remote[0][key] != remote[1][key]
    assert local[0]["a=candidate"].split()[5] == local[1]["a=candidate"].split()[5], "restart changed actual base"
    names = [(a["a=ice-ufrag"] + ":" + b["a=ice-ufrag"]).encode() for a, b in zip(local, remote)]
    lines = (root / "server.log").read_text().splitlines()
    outgoing, incoming, transition_attempts = {}, {}, set()
    counts = [{"checks": 0, "nomination": 0, "probes": 0, "browser_success": 0, "grounds_success": 0} for _ in rounds]
    for row in lines:
        if row.startswith("transmit:"):
            fields = row.split(":")
            generation, source = int(fields[2]), fields[3]
            assert generation in (0, 1)
            raw = bytes.fromhex(fields[-1])
            attrs = validate(raw, remote[generation]["a=ice-pwd"].encode(), "legacy")
            assert raw[:2] == b"\x00\x01"
            assert [value for kind, value, _ in attrs if kind == 6] == [b":".join(names[generation].split(b":")[::-1])]
            kinds = [kind for kind, _, _ in attrs]
            if source == "probe":
                assert 36 not in kinds and 37 not in kinds and 0x8029 not in kinds and 0x802A not in kinds
                counts[generation]["probes"] += 1
            else:
                assert 36 in kinds and 0x8029 in kinds
            outgoing[raw[8:20]] = generation
        elif row.startswith("browser-receive:"):
            raw = bytes.fromhex(row.split(":")[-1])
            if len(raw) < 20 or raw[4:8] != COOKIE:
                continue  # Captured DTLS flights are not processed by Grounds yet.
            attrs = attributes(raw)
            if raw[:2] == b"\x00\x01":
                username = [value for kind, value, _ in attrs if kind == 6]
                assert len(username) == 1
                if username[0] not in names:
                    # During createOffer(iceRestart), Chrome can send its new
                    # local fragment to the previous remote fragment before the
                    # answer arrives. Authenticate it, but require no success or
                    # attempt ownership from that mismatched generation tuple.
                    matches = [g for g, value in enumerate(local) if username[0].split(b":")[0] == value["a=ice-ufrag"].encode()]
                    assert len(matches) == 1, "unknown local credential context"
                    validate(raw, local[matches[0]]["a=ice-pwd"].encode(), "legacy")
                    transition_attempts.add(raw[8:20])
                    continue
                generation = names.index(username[0])
                validate(raw, local[generation]["a=ice-pwd"].encode(), "legacy")
                incoming[raw[8:20]] = generation
                counts[generation]["checks"] += 1
                kinds = [kind for kind, _, _ in attrs]
                if 37 in kinds:
                    assert 36 in kinds and 0x802A in kinds
                    counts[generation]["nomination"] += 1
            elif raw[:2] == b"\x01\x01":
                assert raw[8:20] in outgoing, "unowned browser response"
                generation = outgoing[raw[8:20]]
                validate(raw, remote[generation]["a=ice-pwd"].encode(), "legacy")
                counts[generation]["browser_success"] += 1
        elif row.startswith("reply:"):
            fields = row.split(":")
            generation, code = int(fields[1]), int(fields[2])
            raw = bytes.fromhex(fields[-1])
            assert generation in (0, 1)
            if raw[8:20] in transition_attempts:
                assert code != 0 and raw[:2] == b"\x01\x11", "mixed credentials received success"
                validate(raw, local[generation]["a=ice-pwd"].encode(), "legacy")
                continue
            assert code == 0
            assert raw[8:20] in incoming and incoming[raw[8:20]] == generation
            validate(raw, local[generation]["a=ice-pwd"].encode(), "legacy")
            counts[generation]["grounds_success"] += 1
    for generation, value in enumerate(counts):
        assert all(value[key] > 0 for key in value), (generation, value)
        assert any(row.startswith(f"consent-selected:{generation}:") for row in lines)
        assert any(row.startswith(f"consent-event:{generation}:") and lines[i + 1].startswith("renewed:")
                   for i, row in enumerate(lines[:-1]))
        pair = rounds[generation]["stats"]["iceTransport"]["selected"]
        assert pair["local"]["usernameFragment"] == remote[generation]["a=ice-ufrag"]
        assert pair["remote"]["usernameFragment"] == local[generation]["a=ice-ufrag"]
    assert "restarted:1" in lines and any(row.startswith("signaling-closed:") for row in lines)
    (root / "packets.json").write_text(json.dumps({"generations": counts, "mixed_credential_attempts_without_success": len(transition_attempts), "proof": "independent HMAC-SHA1, FINGERPRINT, USERNAME, transaction, nomination and consent checks"}, indent=2))
    print("Chrome packets: both generations independently authenticated; nomination, one-shot consent and exact session credentials verified")


if __name__ == "__main__":
    main()
