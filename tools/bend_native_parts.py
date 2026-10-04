#!/usr/bin/env python3
"""Compile a recognized Bend CPU C backend in sequential translation units.

Segment bodies and call signatures remain unchanged. Runtime globals and the
dispatch table have one owner; unknown layouts fail before native publication.
Run compilation through build_guard.py, as with bend_native.sh.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


class SplitError(ValueError):
    pass


GLOBALS = frozenset({
    'CORPUS', 'ALC', 'KEEP_WORDS', 'CUBE_LOG', 'bank_lock', 'pool_size',
    'pool_row', 'pool_grow', 'pool_tick', 'pool_done', 'pool_lock', 'pool_wake',
    'BEND_SRC', 'gpu_dev', 'gpu_que', 'gpu_pso', 'gpu_buf', 'gpu_enc',
    'gpu_lib', 'io_gpu', 'io_stk', 'CLI_HELP', 'ERR_TEXT',
})
EXTERNAL_FUNCTIONS = ('f32_show', 'f32_read', 'corpus_grow')
SEGMENT = re.compile(r'^  WL_CASE\((FID_[A-Z0-9_]+)\)\n.*?^  }}\n', re.M | re.S)
LITERALS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def mask(text):
    return LITERALS.sub(lambda match: re.sub(r'[^\n]', ' ', match[0]), text)


def require(condition, message):
    if not condition:
        raise SplitError(message)


def extract(text):
    masked = mask(text)
    matches = list(SEGMENT.finditer(masked))
    names = re.findall(r'^\s*WL_CASE\((FID_[A-Z0-9_]+)\)', masked, re.M)
    require(bool(matches), 'No recognized CPU segments')
    require([match[1] for match in matches] == names, 'Incomplete segment extraction')
    require(len(names) == len(set(names)), 'Duplicate segment IDs')
    bodies = []
    for match in matches:
        body = masked[match.start():match.end()]
        opens = body.count('{') + len(re.findall(r'\bWL_OPEN\b', body))
        require(opens == body.count('}'), f'Unbalanced segment: {match[1]}')
        bodies.append({'name': match[1], 'text': text[match.start():match.end()],
                       'start': match.start(), 'end': match.end()})
    return bodies


def shared_prefix(prefix, source):
    masked = mask(prefix)
    require(not re.search(r'^[ \t]+static\b', masked, re.M),
            'Local static storage cannot be copied into translation units')
    declarations = []
    for match in re.finditer(r'^static\s+([^\n]+)', masked, re.M):
        first = match[1].split('=', 1)[0].split('__attribute__', 1)[0]
        names = [name for name in GLOBALS if re.search(r'\b' + name + r'\b', first)]
        if not names:
            require(not re.search(r'\(\s*\*', first), 'Unknown static function-pointer storage')
            if re.search(r'\b\w+\s*\(', first):
                continue  # static function definition or forward declaration
            raise SplitError('Unknown static global: ' + first.strip())
        require(len(names) == 1, 'Ambiguous static global declaration')
        end = masked.find(';', match.end())
        if ';' in match[1]:
            end = match.start() + masked[match.start():match.end()].index(';')
        require(end >= 0, 'Unterminated global declaration')
        old = prefix[match.start():end + 1]
        definition = old.removeprefix('static ')
        declaration = 'extern ' + definition.split('=', 1)[0].rstrip().removesuffix(';') + ';'
        if names[0] == 'BEND_SRC':
            definition = definition.replace('#embed __FILE__', '#embed ' + json.dumps(str(source)))
        declarations.append((match.start(), end + 1, names[0], definition, declaration))
    require(sum(name == 'ALC' for _, _, name, _, _ in declarations) == 1,
            'Expected one allocator definition')
    for start, end, _, definition, declaration in reversed(declarations):
        prefix = (prefix[:start] + '#ifdef GROUNDS_RUNTIME_OWNER\n' + definition
                  + '\n#else\n' + declaration + '\n#endif' + prefix[end:])
    for name in EXTERNAL_FUNCTIONS:
        prefix, count = re.subn(r'^static ([^\n]*\b' + name + r'\([^\n]*\);)',
                                r'\1', prefix, flags=re.M)
        require(count == 1, 'Missing runtime declaration: ' + name)
    return prefix, [{'name': name, 'definition_sha256': digest(definition.encode()),
                     'declaration': declaration} for _, _, name, definition, declaration in declarations]


def prepare(source, directory, max_bytes=524288, max_segments=128):
    source = source.resolve()
    original = source.read_bytes()
    text = original.decode()
    require(bool(re.search(r'^#define BANGS\s+0$', text, re.M)), 'CPU backend requires BANGS=0')
    require(not re.search(r'^#import ', text, re.M), 'Objective-C backend is not supported by this splitter')
    require(max_bytes > 0 and max_segments > 0, 'Positive partition bounds required')
    segments = extract(text)
    work = text.find('// Work\n')
    loop_match = re.search(r'^static (?:Term|Reply) work_loop\(', text[work:], re.M)
    loop = work + loop_match.start() if loop_match and work >= 0 else -1
    end = text.find('// Segments\n', loop)
    require(0 <= work < loop < end < segments[0]['start'], 'Unrecognized runtime boundaries')
    gap_start = end + len('// Segments\n')
    cpu_guard = False
    for segment in segments:
        gap = mask(text[gap_start:segment['start']])
        for line in gap.splitlines():
            line = line.strip()
            if not line:
                continue
            if line == '#if !DEVICE':
                require(not cpu_guard, 'Nested CPU segment guard')
                cpu_guard = True
            elif line == '#endif':
                require(cpu_guard, 'Unmatched CPU segment guard')
                cpu_guard = False
            else:
                raise SplitError('Unrecognized code between segments')
        segment['cpu_guard'] = cpu_guard
        gap_start = segment['end']
    require(not cpu_guard, 'Unclosed CPU segment guard')
    prefix, globals_ = shared_prefix(text[:work], source)
    prefix, count = re.subn(r'^(#define WL_FN\s+)static ', r'\1', prefix, flags=re.M)
    require(count == 1, 'Unrecognized segment calling-convention macro')
    prelude, count = re.subn(r'^static const WlFn wl_tab\[\] = \{ WL_TABLE \};',
                             'extern const WlFn wl_tab[];', text[work:loop], flags=re.M)
    require(count == 1, 'Unrecognized dispatch table')
    header = ('#ifndef GROUNDS_SPLIT_SHARED\n#define GROUNDS_SPLIT_SHARED\n' + prefix + prelude
              + '\n#if DEVICE || BEND_METAL || BEND_CUDA\n#error CPU C backend required\n#endif\n#endif\n')
    runtime = ('#define GROUNDS_RUNTIME_OWNER\n#include "shared.h"\n'
               '#define WL_X(F) WL_##F,\nconst WlFn wl_tab[] = { WL_TABLE };\n#undef WL_X\n'
               + text[loop:end] + text[segments[-1]['end']:])
    for name in EXTERNAL_FUNCTIONS:
        runtime, count = re.subn(r'^static ([^\n]*\b' + name + r'\([^\n]*\) \{)',
                                 r'\1', runtime, flags=re.M)
        require(count == 1, 'Missing runtime definition: ' + name)
    batches, batch, size = [], [], 0
    for segment in segments:
        length = len(segment['text'].encode())
        if batch and (len(batch) == max_segments or size + length > max_bytes):
            batches.append(batch)
            batch, size = [], 0
        batch.append(segment)
        size += length
    if batch:
        batches.append(batch)
    # Validate before writing any derived source. Directory must be new.
    directory.mkdir()
    (directory / 'shared.h').write_text(header)
    (directory / 'runtime.c').write_text(runtime)
    files = [{'path': 'runtime.c', 'sha256': digest(runtime.encode()), 'segments': []}]
    for index, batch in enumerate(batches):
        path = f'segments-{index:03d}.c'
        body = '#include "shared.h"\n' + ''.join(
            '#if !DEVICE\n' + segment['text'] + '#endif\n' if segment['cpu_guard']
            else segment['text'] for segment in batch)
        (directory / path).write_text(body)
        files.append({'path': path, 'sha256': digest(body.encode()), 'segments': [
            {'name': segment['name'], 'body_sha256': digest(segment['text'].encode())}
            for segment in batch]})
    require([item['name'] for file in files for item in file['segments']]
            == [segment['name'] for segment in segments], 'Partition coverage differs')
    result = {'source': str(source), 'source_sha256': digest(original),
              'segment_count': len(segments), 'shared_header_sha256': digest(header.encode()),
              'runtime_owner': 'runtime.c alone defines globals and dispatch table',
              'globals': globals_, 'max_bytes': max_bytes, 'max_segments': max_segments,
              'body_coverage': 'Every original body, once, in original order', 'files': files}
    (directory / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def compile_parts(directory, compiler, cflags, link_flags, output):
    require(not output.exists() and not output.is_symlink(), 'Output already exists')
    manifest = json.loads((directory / 'manifest.json').read_text())
    require(digest(Path(manifest['source']).read_bytes()) == manifest['source_sha256'], 'C source changed')
    require(digest((directory / 'shared.h').read_bytes()) == manifest['shared_header_sha256'], 'Header changed')
    objects, commands = [], []
    for item in manifest['files']:
        source = directory / item['path']
        require(digest(source.read_bytes()) == item['sha256'], 'Part changed: ' + item['path'])
        target = source.with_suffix('.o')
        require(not target.exists(), 'Object already exists')
        command = [compiler, *cflags, '-c', str(source), '-o', str(target)]
        commands.append(command)
        print('Native CPU part: ' + item['path'], flush=True)
        subprocess.run(command, check=True)
        objects.append(str(target))
    native = directory / 'program'
    require(not native.exists() and not native.is_symlink(), 'Native temporary output already exists')
    commands.append([compiler, *objects, *link_flags, '-o', str(native)])
    (directory / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    subprocess.run(commands[-1], check=True)
    os.link(native, output)
    (directory / 'output.json').write_text(json.dumps({'path': str(output),
        'sha256': digest(output.read_bytes())}, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--max-bytes', type=int, default=524288)
    parser.add_argument('--max-segments', type=int, default=128)
    parser.add_argument('--compiler', default='clang')
    parser.add_argument('--cflag', action='append', default=[])
    parser.add_argument('--link-flag', action='append', default=[])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output:
        require(not args.output.exists() and not args.output.is_symlink(), 'Output already exists')
    manifest = prepare(args.source, args.directory, args.max_bytes, args.max_segments)
    print(f"Native CPU partition: {manifest['segment_count']} segments, {len(manifest['files'])} units", flush=True)
    if args.output:
        compile_parts(args.directory, args.compiler,
                      args.cflag or ['-std=c11', '-O3'], args.link_flag or ['-lpthread', '-lm'], args.output)


if __name__ == '__main__':
    try:
        main()
    except (SplitError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
