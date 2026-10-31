#!/usr/bin/env python3
"""Check the staged Git snapshot for accidental private/generated artifacts.

This is a guardrail, not a substitute for reviewing source provenance.
"""
import ast
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUFFIXES = {'.py', '.S', '.s', '.asm', '.c', '.h', '.inc', '.java', '.md', '.json',
            '.txt', '.map', '.log', '.patch', '.yml', '.yaml'}
NAMES = {'.gitignore', 'LICENSE', 'Makefile'}
PRIVATE_DIRS = {'build', 'private', 'inputs', 'artifacts', '.toolchain', '.venv',
                '__pycache__', '.pytest_cache'}


def main():
    if not (ROOT/'.git').is_dir():
        raise SystemExit('Run in this repository after git init and explicit source staging.')
    entries = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '--stage', '-z'])
    errors = []
    count = 0
    for entry in entries.split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.decode().split('\t', 1)
        mode, oid, stage = metadata.split()
        path = Path(name)
        count += 1
        if mode not in ('100644', '100755') or stage != '0':
            errors.append(f'{name}: symlink, submodule or unresolved index entry')
            continue
        # Historical recipe directories called "inputs" contain only reviewed
        # source metadata. Top-level input/build folders are always private.
        if path.parts[0] in PRIVATE_DIRS or '__pycache__' in path.parts:
            errors.append(f'{name}: private/generated directory')
        if path.suffix not in SUFFIXES and path.name not in NAMES:
            errors.append(f'{name}: unapproved file type')
        data = subprocess.check_output(['git', '-C', str(ROOT), 'cat-file', 'blob', oid])
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            errors.append(f'{name}: binary content')
            continue
        if '\0' in text:
            errors.append(f'{name}: NUL bytes')
        if re.search(r'/' + r'Users/[^/\s]+/', text):
            errors.append(f'{name}: private absolute path')
        if path.suffix == '.py':
            for node in ast.walk(ast.parse(text, filename=name)):
                if not isinstance(node, ast.Constant):
                    continue
                value = node.value
                if (isinstance(value, bytes) and len(value) > 128 or
                    isinstance(value, str) and len(value) > 256 and
                    re.fullmatch(r'[0-9a-fA-F\s]+', value)):
                    errors.append(f'{name}:{node.lineno}: opaque payload literal requires review')
    if not count:
        errors.append('No staged source files found')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'{count} staged text/source files checked; no binary inputs or build products.')


if __name__ == '__main__':
    main()
