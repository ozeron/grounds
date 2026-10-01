"""Require Moon inputs for every crypto module imported by RTC Bend sources."""

from pathlib import Path
import re


def crypto_sources(root: Path) -> set[str]:
    root = root.resolve()
    pending = list((root / "rtc").rglob("*.bend"))
    seen = set()
    while pending:
        path = pending.pop().resolve()
        path.relative_to(root)  # External local imports need explicit handling.
        if path in seen:
            continue
        seen.add(path)
        for spec in re.findall(r"^\s*import\s+(\S+)", path.read_text(), re.M):
            if spec.endswith(".bend"):
                pending.append(path.parent / spec)
    return {str(path.relative_to(root)) for path in seen if path.relative_to(root).parts[0] == "crypto"}


def missing_inputs(root: Path) -> set[str]:
    config = (root / "rtc" / "moon.yml").read_text().split("inputs:", 1)[1]
    patterns = re.findall(r'^\s*-\s*"(/crypto/[^\"]+)"\s*$', config, re.M)
    covered = {str(path.relative_to(root)) for pattern in patterns
               for path in root.glob(pattern.lstrip("/")) if path.is_file()}
    return crypto_sources(root) - covered


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    missing = missing_inputs(root)
    if missing:
        raise SystemExit("RTC imported crypto missing from rtc/moon.yml inputs: "
                         + ", ".join(sorted(missing)))
    print(f"RTC cache inputs: all {len(crypto_sources(root))} imported crypto modules covered")


if __name__ == "__main__":
    main()
