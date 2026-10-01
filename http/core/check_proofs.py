"""Check the complete unchanged law contract and proof bodies in smaller scopes."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
STARTS = {
    "headers": "keep_found",
    "query": "q_same_refl",
    "cookie": "line_safe_clean",
    "cors": "cors_same_refl",
    "multipart": "multipart_end",
    "events": "sapp_assoc",
}
LAWS = {
    "same_ci": "headers", "header_first": "headers", "query_first": "query",
    "set_cookie_clean": "cookie", "cors_safe": "cors",
    "multipart_reads_back": "multipart", "sse_reads_back": "events", "write_joins": "events",
}
EVENT_HELPERS = {"line.clean", "data.clean", "id.clean", "msg.ok", "writable",
                 "stream", "next.id", "read", "events"}


def declarations(source):
    matches = list(re.finditer(r"^(law|def) ([\w.]+)(?=[:(])", source, re.MULTILINE))
    assert len(matches) == len(re.findall(r"^(?:law|def) ", source, re.MULTILINE)), "unrecognized proof declaration"
    return [(match[1], match[2], source[match.start():matches[index + 1].start()
                                      if index + 1 < len(matches) else len(source)])
            for index, match in enumerate(matches)]


def imports(source, bodies):
    code = "\n".join(line for line in bodies.splitlines() if not line.lstrip().startswith("#"))
    used = set(re.findall(r"\b(\w+)\.", code))
    return "import Base\n" + "".join(
        f"import ../{path} as {alias}\n"
        for path, alias in re.findall(r"^import (\S+) as (\w+)$", source, re.MULTILINE)
        if alias in used and alias != "Laws")


def main():
    contract_source = (ROOT / "LAWS.bend").read_text()
    proof_source = (ROOT / "PROOF.bend").read_text()
    contract = declarations(contract_source)
    proofs = declarations(proof_source)
    assert {name for kind, name, _ in contract if kind == "law"} == set(LAWS)
    assert {name for kind, name, _ in contract if kind == "def"} == EVENT_HELPERS
    assert {name.removeprefix("Laws.") for kind, name, _ in proofs
            if kind == "def" and name.startswith("Laws.")} == set(LAWS)
    starts = [next(index for index, (kind, name, _) in enumerate(proofs)
                   if kind == "law" and name == anchor) for anchor in STARTS.values()]
    assert starts[0] == 0 and starts == sorted(set(starts)), "proof group order changed"
    starts.append(len(proofs))
    checked_proofs = checked_contract = 0
    with tempfile.TemporaryDirectory(prefix=".grounds-proof-", dir=ROOT) as directory:
        for index, group in enumerate(STARTS):
            law_rows = [row for row in contract if (LAWS[row[1]] if row[0] == "law" else "events") == group]
            proof_rows = proofs[starts[index]:starts[index + 1]]
            law_body = "".join(row[2] for row in law_rows)
            proof_body = "".join(row[2] for row in proof_rows)
            law_path = Path(directory) / f"{group}_laws.bend"
            proof_path = Path(directory) / f"{group}_proof.bend"
            law_path.write_text(imports(contract_source, law_body) + "\n" + law_body)
            proof_path.write_text(imports(proof_source, proof_body)
                                  + f"import ./{law_path.name} as Laws\n\n" + proof_body)
            print(f"HTTP proofs: {group} ({len(law_rows)} contract, {len(proof_rows)} proof declarations)", flush=True)
            subprocess.run(["bend", str(proof_path)], cwd=ROOT, check=True)
            checked_contract += len(law_rows)
            checked_proofs += len(proof_rows)
    assert checked_contract == len(contract) and checked_proofs == len(proofs)
    print(f"HTTP proofs: all {len(LAWS)} public laws, {checked_contract} contract and {checked_proofs} proof declarations checked")


if __name__ == "__main__":
    main()
