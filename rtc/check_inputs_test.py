"""A new transitive import must not escape the RTC task's declared inputs."""

from pathlib import Path
import tempfile

from check_inputs import crypto_sources, missing_inputs


def main() -> None:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / "rtc" / "examples").mkdir(parents=True)
        (root / "crypto").mkdir()
        (root / "rtc" / "examples" / "main.bend").write_text("import ../../crypto/hmac.bend as H\n")
        (root / "crypto" / "hmac.bend").write_text("import ./sha.bend as S\n")
        (root / "crypto" / "sha.bend").write_text("import Base\n")
        config = root / "rtc" / "moon.yml"
        config.write_text('inputs:\n  - "/crypto/hmac.bend"\n')
        assert missing_inputs(root) == {"crypto/sha.bend"}, "missed a transitive dependency"
        config.write_text('inputs:\n  - "/crypto/hmac.bend"\n  - "/crypto/sha.bend"\n')
        assert missing_inputs(root) == set()
        required = crypto_sources(root)
        (root / "crypto" / "gcm.bend").write_text("import ./helpers/other.bend as O\n")
        assert crypto_sources(root) == required, "unused module changed the closure"
        (root / "crypto" / "sha.bend").write_text("import ./gcm.bend as G\n")
        (root / "crypto" / "helpers").mkdir()
        (root / "crypto" / "helpers" / "other.bend").write_text("import Base\n")
        assert missing_inputs(root) == {"crypto/gcm.bend", "crypto/helpers/other.bend"}
        config.write_text('inputs:\n  - "/crypto/*.bend"\n')
        assert missing_inputs(root) == {"crypto/helpers/other.bend"}, "flat glob covered nested source"
        config.write_text('inputs:\n  - "/crypto/**/*.bend"\n')
        assert missing_inputs(root) == set()
    print("RTC cache guard: transitive additions rejected; complete and unused-module cases passed")


if __name__ == "__main__":
    main()
