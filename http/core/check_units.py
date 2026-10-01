"""Check every original unit definition in a smaller import scope."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
GROUPS = {
    "methods": ("method_", "round_trip_", "status_reason", "other_name"),
    "headers": ("hs", "header_"),
    "query": ("query_", "q_"),
    "request": ("req", "req_"),
    "response": ("res_",),
    "cookie": ("cookie_",),
    "auth": ("bearer_", "basic_", "auth_"),
    "cors": ("cors_",),
    "media": ("content_type_", "multipart_"),
    "text": ("or_default", "u32_"),
    "events": ("evs", "ev_", "fed.es", "rest.evs", "fed.p", "last.of"),
}


def main():
    source = (ROOT / "test.bend").read_text()
    imports = re.findall(r"^import (\./\S+) as (\w+)$", source, re.MULTILINE)
    declarations = list(re.finditer(r"^def ([\w.]+)\(", source, re.MULTILINE))
    assert declarations, "no unit definitions found"
    assert len(declarations) == len(re.findall(r"^def ", source, re.MULTILINE)), "unrecognized unit declaration"
    groups = {name: [] for name in GROUPS}
    for index, declaration in enumerate(declarations):
        name = declaration[1]
        owners = [group for group, selectors in GROUPS.items()
                  if any(name.startswith(selector) if selector.endswith("_") else name == selector
                         for selector in selectors)]
        assert len(owners) == 1, (name, "unit must belong to exactly one group", owners)
        end = declarations[index + 1].start() if index + 1 < len(declarations) else len(source)
        groups[owners[0]].append(source[declaration.start():end])
    checked = 0
    with tempfile.TemporaryDirectory(prefix=".grounds-unit-", dir=ROOT) as directory:
        for group, bodies in groups.items():
            assert bodies, (group, "empty unit group")
            body = "".join(bodies)
            code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
            used = set(re.findall(r"\b(\w+)\.", code))
            header = "import Base\n" + "".join(
                f"import ../{path[2:]} as {alias}\n" for path, alias in imports if alias in used)
            path = Path(directory) / f"{group}.bend"
            path.write_text(header + "\n" + body)
            print(f"HTTP units: {group} ({len(bodies)} definitions)", flush=True)
            subprocess.run(["bend", str(path)], cwd=ROOT, check=True)
            checked += len(bodies)
    assert checked == len(declarations)
    print(f"HTTP units: all {checked} original definitions checked exactly once")


if __name__ == "__main__":
    main()
