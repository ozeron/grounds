"""Protect the cold-type gate without invoking Bend or compiling fixtures."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cold import hot_constructors


NAMES = "#define CID_NIL 0\n#define CID_CON 1\n#define CID_UNIT 2\n"
LEGACY = NAMES + "const u8 CID_HOT_T[] = {0, 0, 0};\n" + \
    "#define cid_hot(x) ((bool)CID_HOT_T[x])\n"
COMBINED = NAMES + "CONSTV u8 CID_T[][2] = { {0, 0}, {2, 0}, {0, 0} };\n" + \
    "#define cid_hot(x)   ((bool)CID_T[x][1])\n"


class ColdTests(unittest.TestCase):
    def test_cold_in_both_layouts(self):
        for text in (LEGACY, COMBINED):
            with self.subTest(text=text):
                self.assertEqual(hot_constructors(text), [])

    def test_hot_flags_are_independent_of_arity(self):
        self.assertEqual(hot_constructors(LEGACY.replace("{0, 0, 0}", "{1, 0, 1}")),
                         ["NIL", "UNIT"])
        self.assertEqual(hot_constructors(COMBINED.replace("{0, 0}", "{0, 1}")),
                         ["NIL", "UNIT"])

    def test_multiline_tables_and_trailing_comma(self):
        text = COMBINED.replace("{ {0, 0}, {2, 0}, {0, 0} }",
                                "{\n {0, 0},\n {2, 0},\n {0, 1},\n }")
        self.assertEqual(hot_constructors(text), ["UNIT"])
        self.assertEqual(hot_constructors(LEGACY.replace("{0, 0, 0}", "{\n0, 0, 1,\n}")),
                         ["UNIT"])

    def test_unknown_or_inconsistent_metadata_fails(self):
        cases = [
            "", LEGACY + COMBINED, COMBINED + COMBINED,
            COMBINED.replace("[x][1]", "[x][0]"),
            COMBINED.replace("{2, 0}", "{2, 2}"),
            COMBINED.replace("{2, 0}", "{2}"),
            COMBINED.replace("{2, 0}", "{2, 0, 0}"),
            COMBINED.replace("{2, 0}", "{2, 0}, unknown"),
            COMBINED.replace("#define CID_CON 1\n", ""),
            COMBINED.replace("#define CID_CON 1", "#define CID_CON 0"),
            COMBINED.replace("#define CID_CON 1", "#define CID_NIL 1"),
            COMBINED.replace("[][2]", "[][3]"),
            LEGACY.replace("{0, 0, 0}", "{0, -1, 0}"),
            LEGACY.replace("{0, 0, 0}", "{}"),
            LEGACY.replace("[x]", "[x + 1]"),
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                hot_constructors(text)

    def test_cli_cold_hot_unknown_and_failed_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = root / "bend"
            compiler.write_text(
                f"#!{sys.executable}\n"
                "import os,pathlib,sys\n"
                "if sys.argv[1] == 'failed.bend': sys.exit(7)\n"
                "pathlib.Path(sys.argv[sys.argv.index('-o') + 1]).write_text(os.environ['COLD_TEST_C'])\n"
            )
            compiler.chmod(0o755)
            environment = {**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"]}
            script = Path(__file__).with_name("cold.py")
            for source, text, code, message in (
                ("cold.bend", COMBINED, 0, "cold.bend: cold"),
                ("hot.bend", COMBINED.replace("{2, 0}", "{2, 1}"), 1, "hot constructors: CON"),
                ("unknown.bend", "", 1, "cannot verify cold constructors"),
                ("failed.bend", COMBINED, 1, "returned non-zero exit status 7"),
            ):
                with self.subTest(source=source):
                    result = subprocess.run([sys.executable, str(script), source],
                                            env={**environment, "COLD_TEST_C": text},
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertIn(message, result.stdout + result.stderr)
                    if code:
                        self.assertNotIn(f"{source}: cold\n", result.stdout)

    def test_cli_requires_a_program(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("cold.py"))],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn("usage: cold.py", result.stderr)


if __name__ == "__main__":
    unittest.main()
