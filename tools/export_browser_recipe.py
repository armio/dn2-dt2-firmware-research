#!/usr/bin/env python3
"""Export an audited browser recipe; refuse any unexplained output bytes.

The private plan supplies input/target paths and reviewed original adapter
artifacts. The public result contains copy coordinates and provenance only.
It never infers literal patches from a binary diff.
"""
import argparse
import base64
import hashlib
import json
import math
from pathlib import Path
import struct


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked(path, digest, size):
    data = Path(path).read_bytes()
    if len(data) != size or sha(data) != digest:
        raise ValueError(f"Artifact identity mismatch: {path}")
    return data


def original_data(name):
    if name == 'silent-compatibility-bank':
        return struct.pack('<11I', 0x3142534f, 3, 0x31182c, 2708, 48000,
                           0x314d54, 2723, 48000, 0x31829c, 3145, 48000).ljust(47104, b'\0')
    if name == 'pitch-table':
        return b''.join(struct.pack('<q', round(0.5 * 2 ** ((tune - 64) / 12) * 2 ** 31) * sign)
                        for sign in (1, -1) for tune in range(128))
    if name not in ('chirp-bank', 'chirp-cache'):
        raise ValueError(f'Unsupported original data generator: {name}')
    pcm, phase, k = [], 0.0, math.log(8) / 7200
    for i in range(7200):
        phase += 2 * math.pi * (220 * math.exp(k * i)) / 48000
        value = max(-32768, min(32767, round(0.9 * 10 ** (-i / 7200) * math.sin(phase) * 32768)))
        pcm.append(round(value / 32768 * 32767))
    if name == 'chirp-bank':
        return (struct.pack('<5I', 0x3142534f, 1, 0x311814, 7200, 48000) + bytes(4096) +
                struct.pack('<7200h', *pcm) + bytes(4096))
    cache = bytearray(404)
    for x in range(96):
        values = [n >> 8 for n in pcm[x * 7200 // 96:(x + 1) * 7200 // 96]]
        cache[0x10 + x] = max([0] + values) & 255
        cache[0x70 + x] = min([0] + values) & 255
    return bytes(cache)


def computed_data(name, data):
    """Values derived from the user's own OS input during the build; the recipe names only the formula."""
    if name == 'sem-graph-log-cutoff' and len(data) == 4096:
        # R026: Q8 log2 of the native cutoff coefficient at 129 FREQ steps (kernel bound applied)
        # and at the 49 graph columns. Matches port/sem-filter/tree/scripts/sem_graph_reference.py.
        g = struct.unpack('<1024f', data)

        def at(raw):
            pos = min(1023.0, raw / 32)
            i = int(pos)
            return g[i] if i >= 1023 else g[i] + (pos - i) * (g[i + 1] - g[i])
        lt = [round(256 * math.log2(min(6.3137515, at(k * 256)))) for k in range(129)]
        lx = [round(256 * math.log2(at((x - 22) * 32768 / 48))) for x in range(22, 71)]
        return struct.pack('>178h', *lt, *lx)
    if name == 'sem-type-planes' and len(data) == 76:
        # R027: TYPE icon planes; the middle icon flipped vertically, then the middle icon alone.
        words = struct.unpack('>19I', data)
        sem, bp = list(words), [0] * 19
        for c in range(7, 12):
            keep = sum(words[c] & 1 << (31 - r) for r in range(4, 9))
            flipped = sum(1 << (31 - (12 - r)) for r in range(4, 9) if words[c] & 1 << (31 - r))
            sem[c] = words[c] & ~keep & 0xffffffff | flipped
            bp[c] = keep
        return struct.pack('>38I', *sem, *bp)
    raise ValueError(f'Unsupported computed source: {name}')


def provenance(value, root):
    """Require a source file identity, not a reviewer boolean or a local path."""
    if not isinstance(value, dict) or set(value) != {'source', 'sha256', 'reason'}:
        raise ValueError('Provenance requires source, sha256 and reason')
    relative = Path(value['source'])
    if relative.is_absolute() or '..' in relative.parts or not value['reason'].strip():
        raise ValueError('Invalid public source provenance')
    path = root / relative
    if not path.is_file() or sha(path.read_bytes()) != value['sha256']:
        raise ValueError(f"Source provenance mismatch: {relative}")
    return dict(value)


def checked_operations(expected, operations, private, root, label):
    result, public_ops = bytearray(), []
    for op in operations:
        kind = op['kind']
        if kind == 'copy':
            data = private[op['source']]
            offset, size = op['offset'], op['bytes']
            if offset < 0 or size <= 0 or offset + size > len(data):
                raise ValueError('Copy outside source')
            piece = data[offset:offset + size]
            public = {k: op[k] for k in ('kind', 'source', 'offset', 'bytes')}
        elif kind == 'fill':
            if op['value'] != 0 or op['bytes'] < 1:
                raise ValueError('Only explicit zero-fill is accepted')
            piece = bytes(op['bytes'])
            public = {k: op[k] for k in ('kind', 'value', 'bytes')}
        elif kind == 'scalar':
            proof = provenance(op['provenance'], root)
            if op['bytes'] not in (1, 2, 4) or op['endian'] not in ('big', 'little'):
                raise ValueError('Invalid scalar width or byte order')
            piece = op['value'].to_bytes(op['bytes'], op['endian'])
            public = {k: op[k] for k in ('kind', 'value', 'bytes', 'endian')}
            public['provenance'] = proof
        else:
            raise ValueError(f'Unsupported operation: {kind}')
        at = len(result)
        if expected[at:at + len(piece)] != piece:
            raise ValueError(f'{label}: operation differs at 0x{at:x}')
        result.extend(piece)
        public_ops.append(public)
    if bytes(result) != expected:
        raise ValueError(f'{label}: unexplained bytes from 0x{len(result):x}; no recipe exported')
    return public_ops


def export(plan, root):
    sources, private = {}, {}
    for identity, spec in plan['sources'].items():
        data = checked(spec['path'], spec['sha256'], spec['bytes'])
        if spec['kind'] == 'firmware':
            if spec['input'] not in ('dn2', 'dt2') or spec['section'] not in (3, 7):
                raise ValueError('Only pinned official MAIN/DSP sources are supported')
            sources[identity] = {k: spec[k] for k in ('kind', 'input', 'section', 'sha256', 'bytes')}
        elif spec['kind'] == 'adapter':
            proofs = [provenance(p, root) for p in spec['provenance']]
            if not proofs or not spec.get('toolchain_sha256'):
                raise ValueError('Adapter requires source and toolchain provenance')
            # An object containing donor bytes must be materialized with holes
            # before it is supplied here. Browser fills those holes using COPY.
            for hole in spec.get('donor_holes', []):
                start, size = hole['offset'], hole['bytes']
                if start < 0 or size < 1 or start + size > len(data):
                    raise ValueError('Invalid donor hole')
                if any(data[start:start + size]):
                    raise ValueError('Adapter still contains bytes in a donor hole')
            sources[identity] = {
                'kind': 'adapter', 'sha256': spec['sha256'], 'bytes': spec['bytes'],
                'provenance': proofs, 'toolchain_sha256': spec['toolchain_sha256'],
                'donor_holes': spec.get('donor_holes', []),
                'base64': base64.b64encode(data).decode('ascii'),
            }
        elif spec['kind'] == 'generated':
            if original_data(spec['generator']) != data:
                raise ValueError(f'Generated source differs: {identity}')
            sources[identity] = {
                'kind': 'generated', 'generator': spec['generator'],
                'sha256': spec['sha256'], 'bytes': spec['bytes'],
                'provenance': [provenance(p, root) for p in spec['provenance']],
            }
        elif spec['kind'] == 'computed':
            source = spec['input']
            if (set(source) != {'source', 'offset', 'bytes'} or source['source'] not in private or
                    sources[source['source']]['kind'] != 'firmware'):
                raise ValueError(f'Computed input must name an earlier official OS section: {identity}')
            start, size = source['offset'], source['bytes']
            parent = private[source['source']]
            if start < 0 or size < 1 or start + size > len(parent):
                raise ValueError(f'Computed input outside source: {identity}')
            if computed_data(spec['generator'], parent[start:start + size]) != data:
                raise ValueError(f'Computed source differs: {identity}')
            sources[identity] = {
                'kind': 'computed', 'generator': spec['generator'], 'input': dict(source),
                'sha256': spec['sha256'], 'bytes': spec['bytes'],
                'provenance': [provenance(p, root) for p in spec['provenance']],
            }
        elif spec['kind'] == 'derived':
            sources[identity] = {
                'kind': 'derived', 'sha256': spec['sha256'], 'bytes': spec['bytes'],
                'provenance': [provenance(p, root) for p in spec['provenance']],
                'operations': checked_operations(data, spec['operations'], private, root, identity),
            }
        else:
            raise ValueError(f"Unsupported source kind: {spec['kind']}")
        private[identity] = data

    images = {}
    for name, target in plan['images'].items():
        expected = checked(target['path'], target['sha256'], target['bytes'])
        operations = checked_operations(expected, target['operations'], private, root, name)
        images[name] = {'sha256': target['sha256'], 'bytes': target['bytes'],
                        'operations': operations}
    return {'schema': 1, 'release': plan['release'], 'inputs': plan['inputs'],
            'sources': sources, 'images': images,
            'postprocess': plan.get('postprocess', {})}


def copy_coverage(target, sources, minimum=16):
    """Suggest exact copies only; report remaining ranges without their bytes.

    This is an audit aid, not an exporter: any unexplained range must acquire
    reviewed source provenance before export() accepts a final plan.
    """
    index = {}
    for name, data in sources.items():
        for at in range(0, len(data) - minimum + 1, 2):
            key = data[at:at + minimum]
            if not any(key):
                continue
            candidates = index.setdefault(key, [])
            if len(candidates) < 8:
                candidates.append((name, at))
    operations, unknown, at = [], [], 0
    while at < len(target):
        zero_end = at
        if target[at:at + minimum] == bytes(minimum):
            while zero_end < len(target) and target[zero_end] == 0:
                zero_end += 1
        best = (zero_end - at, None, 0)
        for name, source_at in index.get(target[at:at + minimum], []):
            data, size = sources[name], minimum
            limit = min(len(data) - source_at, len(target) - at)
            while size < limit and data[source_at + size] == target[at + size]:
                size += 1
            if size > best[0]:
                best = (size, name, source_at)
        size, name, source_at = best
        if size >= minimum:
            if name is None:
                operations.append(dict(kind='fill', value=0, bytes=size))
            else:
                operations.append(dict(kind='copy', source=name, offset=source_at, bytes=size))
            at += size
        else:
            if unknown and unknown[-1]['offset'] + unknown[-1]['bytes'] == at:
                unknown[-1]['bytes'] += 1
                operations[-1]['bytes'] += 1
            else:
                unknown.append(dict(offset=at, bytes=1))
                operations.append(dict(kind='unexplained', bytes=1))
            at += 1
    return {'bytes': len(target), 'covered_bytes': len(target) - sum(r['bytes'] for r in unknown),
            'unexplained': unknown, 'operations': operations}


def merge_candidates(coverage, candidates, target):
    """Overlay reviewed scalar/copy spans, keeping their complete field widths."""
    operations = list(coverage['operations'])
    owners, starts = [], []
    for number, op in enumerate(operations):
        starts.append(len(owners))
        owners.extend([number] * op['bytes'])
    for candidate in candidates:
        start, size = candidate['offset'], candidate['bytes']
        if start < 0 or size < 1 or start + size > len(target):
            raise ValueError('Candidate exceeds target')
        existing = {owners[i] for i in range(start, start + size)}
        if not any(operations[i]['kind'] == 'unexplained' for i in existing):
            continue
        if any(operations[i]['kind'] == 'scalar' and
               (starts[i] < start or starts[i] + operations[i]['bytes'] > start + size)
               for i in existing):
            continue
        op = dict(candidate)
        del op['offset']
        if op['kind'] == 'scalar':
            if target[start:start + size] != op['value'].to_bytes(size, op['endian']):
                raise ValueError('Scalar candidate differs from target')
        elif op['kind'] == 'copy':
            op['offset'] = op.pop('source_offset')
        elif op['kind'] == 'fill':
            if op.get('value') != 0 or any(target[start:start + size]):
                raise ValueError('Only checked zero-fill candidates are supported')
        else:
            raise ValueError('Unsupported candidate')
        owners[start:start + size] = [len(operations)] * size
        starts.append(start)
        operations.append(op)
    result, unknown, at = [], [], 0
    while at < len(target):
        number, end = owners[at], at + 1
        while end < len(target) and owners[end] == number:
            end += 1
        op = dict(operations[number])
        if op['kind'] == 'copy':
            op['offset'] += at - starts[number]
        elif op['kind'] == 'scalar':
            if at != starts[number] or end - at != op['bytes']:
                raise ValueError('Candidate split a scalar field')
        elif op['kind'] == 'unexplained':
            unknown.append(dict(offset=at, bytes=end - at))
        op['bytes'] = end - at
        result.append(op)
        at = end
    return {'bytes': len(target), 'covered_bytes': len(target) - sum(r['bytes'] for r in unknown),
            'unexplained': unknown, 'operations': result}


def anchored_copies(coverage, mappings, sources, target):
    """Recover short unchanged runs only inside explicitly mapped donor spans."""
    candidates = []
    for mapping in mappings:
        start, size = mapping['offset'], mapping['bytes']
        source, source_at = sources[mapping['source']], mapping['source_offset']
        if min(start, source_at) < 0 or source_at + size > len(source) or start + size > len(target):
            raise ValueError('Mapped donor span exceeds bounds')
        for gap in coverage['unexplained']:
            at, limit = max(start, gap['offset']), min(start + size, gap['offset'] + gap['bytes'])
            while at < limit:
                if target[at] != source[source_at + at - start]:
                    at += 1
                    continue
                end = at + 1
                while end < limit and target[end] == source[source_at + end - start]:
                    end += 1
                candidates.append(dict(kind='copy', source=mapping['source'], offset=at,
                                       source_offset=source_at + at - start, bytes=end - at))
                at = end
    return merge_candidates(coverage, candidates, target)


def zero_gaps(coverage, target):
    candidates = []
    for gap in coverage['unexplained']:
        at, limit = gap['offset'], gap['offset'] + gap['bytes']
        while at < limit:
            if target[at] != 0:
                at += 1
                continue
            end = at + 1
            while end < limit and target[end] == 0:
                end += 1
            candidates.append(dict(kind='fill', offset=at, value=0, bytes=end - at))
            at = end
    return merge_candidates(coverage, candidates, target)


def neighboring_copies(coverage, sources, target, distance=64):
    """Extend existing affine source mappings across adjacent patched fields.

    Unlike a two-byte dictionary search, this keeps the source's position
    relative to the established copy. Nonmatching operands remain unexplained.
    """
    anchors, at = [], 0
    for op in coverage['operations']:
        if op['kind'] == 'copy':
            source_size = len(sources[op['source']])
            left = min(distance, at, op['offset'])
            right = min(distance, len(target) - at - op['bytes'],
                        source_size - op['offset'] - op['bytes'])
            anchors.append(dict(offset=at - left, source=op['source'],
                                source_offset=op['offset'] - left,
                                bytes=left + op['bytes'] + right))
        at += op['bytes']
    return anchored_copies(coverage, anchors, sources, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True,
                        help='Private reviewed plan; paths and outputs are never copied into recipe')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--source-root', type=Path,
                        default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    recipe = export(json.loads(args.plan.read_text()), args.source_root.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x') as output:
        output.write(json.dumps(recipe, separators=(',', ':')) + '\n')
    print(f"Exported reviewed {recipe['release']} recipe")


if __name__ == '__main__':
    main()
