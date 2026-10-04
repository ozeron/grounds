"""Publication, storage and calling-convention regressions for the splitter."""
import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

import bend_native_parts as Parts


class NativePartsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source.c'
        self.original = (Path(__file__).parent / 'testdata/native_parts.c').read_text()
        self.source.write_text(self.original)

    def rejected(self, source, message):
        self.source.write_text(source)
        with self.assertRaisesRegex(Parts.SplitError, message):
            Parts.prepare(self.source, self.root / 'parts')
        self.assertFalse((self.root / 'parts').exists())

    def test_unknown_global_rejected_before_writes(self):
        self.rejected(self.original.replace('static u64 ALC[1];',
                      'static u64 ALC[1];\nstatic u64 hidden_counter;'), 'Unknown static global')

    def test_local_static_rejected_before_writes(self):
        self.rejected(self.original.replace('// Work',
                      'static void cache(void) {\n  static u64 hidden;\n}\n// Work'), 'Local static')

    def test_gpu_rejected_before_writes(self):
        self.rejected(self.original.replace('#define BANGS 0', '#define BANGS 1'), 'BANGS=0')

    def test_missing_body_rejected_before_writes(self):
        self.rejected(self.original.replace('  }}\nstatic Term f32_show',
                      '  }\nstatic Term f32_show'), 'Incomplete segment extraction')

    def test_braces_in_literal_do_not_end_body(self):
        source = self.original.replace('    ALC[0] = 10;',
                                       '    const char* ignored = "}};";\n    ALC[0] = 10;')
        bodies = Parts.extract(source)
        self.assertEqual(len(bodies), 3)
        self.assertIn('"}};"', bodies[0]['text'])

    def test_code_between_segments_is_not_discarded(self):
        self.rejected(self.original.replace('  WL_CASE(FID_COUNT)',
                      'static u64 hidden_counter;\n  WL_CASE(FID_COUNT)'), 'between segments')

    def test_cpu_wrappers_are_preserved(self):
        source = self.original.replace('  WL_CASE(FID_ENTER)', '#if !DEVICE\n  WL_CASE(FID_ENTER)')
        source = source.replace('  WL_CASE(FID_COUNT)', '#endif\n  WL_CASE(FID_COUNT)')
        self.source.write_text(source)
        directory = self.root / 'parts'
        manifest = Parts.prepare(self.source, directory, max_segments=1)
        part = (directory / manifest['files'][1]['path']).read_text()
        self.assertIn('#if !DEVICE\n  WL_CASE(FID_ENTER)', part)
        self.assertTrue(part.endswith('#endif\n'))
        output = self.root / 'program'
        with contextlib.redirect_stdout(io.StringIO()):
            Parts.compile_parts(directory, 'clang', ['-std=c11', '-O3'], [], output)
        self.assertEqual(subprocess.check_output([str(output)], text=True), '11\n')

    def test_runtime_local_storage_has_one_owner(self):
        source = self.original.replace('int main(void) {',
            'static u64 tick(void) {\n  static u64 counter;\n  return ++counter;\n}\nint main(void) {')
        source = source.replace('  return 0;\n}',
            '  printf("%llu\\n", (unsigned long long)tick());\n'
            '  printf("%llu\\n", (unsigned long long)tick());\n  return 0;\n}')
        self.source.write_text(source)
        directory = self.root / 'parts'
        Parts.prepare(self.source, directory, max_segments=1)
        self.assertEqual(sum(path.read_text().count('static u64 counter;')
                             for path in [directory / 'shared.h', *directory.glob('*.c')]), 1)
        output = self.root / 'program'
        with contextlib.redirect_stdout(io.StringIO()):
            Parts.compile_parts(directory, 'clang', ['-std=c11', '-O3'], [], output)
        self.assertEqual(subprocess.check_output([str(output)], text=True), '11\n1\n2\n')

    def test_mutations_survive_direct_and_dynamic_cross_unit_calls(self):
        directory = self.root / 'parts'
        Parts.prepare(self.source, directory, max_segments=1)
        output = self.root / 'program'
        with contextlib.redirect_stdout(io.StringIO()):
            Parts.compile_parts(directory, 'clang', ['-std=c11', '-O3'], [], output)
        self.assertEqual(subprocess.check_output([str(output)], text=True), '11\n')

    def test_existing_output_is_preserved(self):
        directory = self.root / 'parts'
        Parts.prepare(self.source, directory)
        output = self.root / 'existing'
        output.write_bytes(b'unrelated')
        with self.assertRaisesRegex(Parts.SplitError, 'already exists'):
            Parts.compile_parts(directory, 'clang', [], [], output)
        self.assertEqual(output.read_bytes(), b'unrelated')

    def test_output_created_during_link_is_preserved(self):
        directory = self.root / 'parts'
        Parts.prepare(self.source, directory)
        output = self.root / 'concurrent-output'
        compiler = self.root / 'compiler'
        compiler.write_text('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n'
                            'target = Path(sys.argv[sys.argv.index("-o") + 1])\n'
                            'target.write_bytes(b"compiled")\n'
                            'if "-c" not in sys.argv:\n'
                            f'    Path({str(output)!r}).write_bytes(b"unrelated")\n')
        compiler.chmod(0o700)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(FileExistsError):
            Parts.compile_parts(directory, str(compiler), [], [], output)
        self.assertEqual(output.read_bytes(), b'unrelated')


if __name__ == '__main__':
    unittest.main()
