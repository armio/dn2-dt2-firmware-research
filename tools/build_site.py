#!/usr/bin/env python3
"""Stage only reviewed browser assets; never package firmware inputs or outputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
FILES = ('index.html', 'style.css', 'app.js', 'build-worker.js', 'recipe.js',
         'firmware-codec.js', 'generated.js', 'codec-native.mjs', 'codec-native.wasm',
         'codec-LICENSE.txt', 'recipe.json')


def build(output):
    release = json.loads((ROOT/'releases/r012.json').read_text())
    recipe = json.loads((ROOT/'web/recipe.json').read_text())
    if (recipe.get('release') != release['build'] or recipe.get('schema') != 1 or
            recipe.get('inputs') != release['inputs']):
        raise ValueError('Browser recipe and release differ')
    for image, key in (('main_expanded', 'expanded_main_sha256'), ('dsp', 'dsp_sha256')):
        identity = recipe['images'][image]
        if identity['sha256'] != release['outputs'][key]:
            raise ValueError(f'{image}: release identity differs')
        if sum(op['bytes'] for op in identity['operations']) != identity['bytes']:
            raise ValueError(f'{image}: incomplete recipe')
    proofs = []
    for spec in recipe['sources'].values():
        if spec['kind'] in ('adapter', 'generated', 'derived'):
            proofs.extend(spec['provenance'])
    for image in [*recipe['images'].values(),
                  *(spec for spec in recipe['sources'].values() if spec['kind'] == 'derived')]:
        for op in image['operations']:
            if op['kind'] not in ('copy', 'fill', 'scalar'):
                raise ValueError('Unreviewed recipe operation')
            if 'provenance' in op:
                proofs.append(op['provenance'])
    for proof in proofs:
        path = Path(proof['source'])
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('Non-public source provenance')
        actual = hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
        if actual != proof['sha256']:
            raise ValueError(f'Source provenance changed: {path}')
    codec = json.loads((ROOT/'web/codec-build.json').read_text())
    for name, expected in codec['sources'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != expected:
            raise ValueError(f'Codec source changed: {name}')
    for name in FILES:
        path = ROOT/'web'/name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'Missing or unreviewed site asset: {name}')
    output.mkdir(parents=True, exist_ok=False)
    for name in FILES:
        shutil.copyfile(ROOT/'web'/name, output/name)
    (output/'release.json').write_text(json.dumps(release, indent=2)+'\n')
    print(f'Staged {len(FILES)+1} browser assets; no firmware inputs or outputs.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
