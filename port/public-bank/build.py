#!/usr/bin/env python3
"""R012 onward: two official inputs, generated silence, exact reviewed hashes."""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SHA = lambda data: hashlib.sha256(data).hexdigest()
HEX = re.compile(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')
BANK_BYTES = 47104
BANK_OFFSET = 0x323ec0
DIRECTORY = ((0x31182c, 2708, 48000), (0x314d54, 2723, 48000),
             (0x31829c, 3145, 48000))


def silent_bank():
    """Preserve the historical allocation geometry; contain no recorded audio."""
    header = struct.pack('<11I', 0x3142534f, 3, *(v for row in DIRECTORY for v in row))
    return header + bytes(BANK_BYTES - len(header))


def load_profile():
    profile = json.loads((HERE/'hashes.json').read_text())
    replacements = profile['replacements']
    if not replacements or any(not re.fullmatch('[0-9a-f]{64}', old) or
                               not re.fullmatch('[0-9a-f]{64}', new) or old == new
                               for old, new in replacements.items()):
        raise ValueError('Invalid public-bank hash profile')
    if profile['bank']['sha256'] != SHA(silent_bank()) or profile['bank']['bytes'] != BANK_BYTES:
        raise ValueError('Generated silent bank differs from its reviewed profile')
    return profile


def materialize(source, target, profile):
    """Copy reviewed source only; substitute pinned identities, never assertions."""
    if target.exists():
        raise FileExistsError(f'Choose a fresh source projection: {target}')
    replacements, seen = profile['replacements'], set()
    target.mkdir(parents=True)

    def replace(match):
        old = match.group()
        if old in replacements:
            seen.add(old)
            return replacements[old]
        return old

    for name in ('build.py', 'port', 'tools', 'research', 'releases'):
        entry = source/name
        candidates = [entry] if entry.is_file() else sorted(entry.rglob('*'))
        for path in candidates:
            relative = path.relative_to(source)
            if ('public-bank' in relative.parts or '__pycache__' in relative.parts
                    or path.name == '.DS_Store' or path.suffix == '.pyc'):
                continue
            if path.is_symlink():
                raise ValueError(f'Source projection refuses symlinks: {relative}')
            if not path.is_file():
                continue
            text = path.read_text()
            if '\0' in text:
                raise ValueError(f'Source projection refuses binary content: {relative}')
            output = target/relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(HEX.sub(replace, text))
    missing = set(replacements) - seen
    if missing:
        raise ValueError(f'Hash profile contains {len(missing)} unused substitutions')
    for build, lengths in profile['release_outputs'].items():
        path = target/'releases'/f'{build.lower()}.json'
        release = json.loads(path.read_text())
        if release['outputs']['sysex_bytes'] != lengths['original_sysex_bytes']:
            raise ValueError(f'{build} original container length differs')
        release['outputs']['sysex_bytes'] = lengths['sysex_bytes']
        path.write_text(json.dumps(release, indent=2)+'\n')
    return len(seen)


def stage_identity(parent, out, source):
    """Retain the projected R011 image, changing only identity and tail lengths."""
    sys.path[:0] = [str(parent.parent/'scripts'), str(source/'research/audits'),
                   str(source/'port/dsp/support'), str(source/'port/tools/dnfw/src')]
    T = importlib.import_module('build_dn2_recovery_tail')
    staged = (parent/'main-os.bin').read_bytes()
    original = json.loads((parent/'build-receipt.json').read_text())
    if original.get('build') != 'R011':
        raise ValueError('R012 requires the projected R011 parent')
    raw = bytearray(T.expand_verified(staged, original))
    if raw[BANK_OFFSET:BANK_OFFSET+BANK_BYTES] != silent_bank():
        raise ValueError('Projected MAIN does not contain the generated silent bank')
    runtime = bytearray((parent/'runtime.bin').read_bytes())
    copy_region = original['runtime_copy']
    at = int(copy_region['source'], 16)-T.BASE
    marker = 0x47aa5a0c-T.SCRATCH
    if (SHA(runtime) != original['runtime_sha256'] or
            raw[at:at+len(runtime)] != runtime or runtime[marker:marker+4] != b'R011'):
        raise ValueError('Projected R011 runtime identity differs')
    runtime[marker:marker+4] = b'R012'
    raw[at:at+len(runtime)] = runtime
    tail = bytes(raw[T.CUT-T.BASE:])
    blob = T.compress(3, T.CUT, tail).stored
    if (len(blob) > copy_region['bytes'] or
            T.SCRATCH+len(blob) > int(original['runtime_limit'], 16) or
            T.aplib.depack(blob[8:]) != tail):
        raise ValueError('R012 tail exceeds its reservation or fails roundtrip')
    wrapper = T.wrapper_bytes(len(blob), len(tail))
    if len(wrapper) > T.CAVE_BYTES:
        raise ValueError('R012 loader wrapper exceeds its cave')
    raw[T.CAVE-T.BASE:T.CAVE-T.BASE+len(wrapper)] = wrapper
    expanded = bytes(raw)
    staged = expanded[:T.CUT-T.BASE]+blob
    doc = copy.deepcopy(original)
    metadata = doc['boot_tail']
    metadata.pop('identity_profile', None)
    metadata.update(stored_bytes=len(blob), expanded_tail_bytes=len(tail),
        stored_sha256=SHA(blob), tail_sha256=SHA(tail), wrapper_bytes=len(wrapper),
        wrapper_sha256=SHA(wrapper), expanded_main_sha256=SHA(expanded),
        expanded_main_bytes=len(expanded))
    doc.pop('main_identity_only', None)
    doc.update(build='R012', main_sha256=SHA(staged), bytes=len(staged),
               runtime_sha256=SHA(runtime), public_bank=dict(bytes=BANK_BYTES,
               sha256=SHA(silent_bank()), contains_recorded_audio=False))
    for patch in doc['frame_recorder']['patches']:
        if patch['name'] == 'identity':
            patch['after'] = b'R012'.hex()
    if T.expand_verified(staged, doc) != expanded:
        raise ValueError('R012 staged projection differs')
    out.mkdir(parents=True, exist_ok=False)
    for name, data in (('main-os.bin', staged), ('runtime.bin', runtime), ('tail.aplib', blob)):
        (out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    flat = out/'expanded'
    flat.mkdir()
    flat_doc = copy.deepcopy(doc)
    flat_doc.pop('boot_tail')
    flat_doc.update(main_sha256=SHA(expanded), bytes=len(expanded), staged_main_sha256=SHA(staged))
    (flat/'main-os.bin').write_bytes(expanded)
    (flat/'runtime.bin').write_bytes(runtime)
    (flat/'build-receipt.json').write_text(json.dumps(flat_doc, indent=2)+'\n')
    for name in ('fn_new_map.txt', 'ram_map.txt', 'bootstrap.S'):
        shutil.copyfile(parent/name, out/name)
        shutil.copyfile(parent/name, flat/name)
    return doc


def build(args):
    from tools.check_inputs import inputs, verify
    private = inputs(args.dn2, args.dt2, args.sample_bank, target=args.target)
    release = json.loads((ROOT/'releases'/f'{args.target.lower()}.json').read_text())
    profile = load_profile()
    paths = json.loads(args.toolchain.read_text())
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        raise ValueError('--out must be outside the source repository')
    if out.exists():
        raise FileExistsError(f'Refusing to overwrite {out}')
    if args.work:
        work = args.work.resolve()
        if work == ROOT or ROOT in work.parents:
            raise ValueError('--work must be outside the source repository')
        work.mkdir(parents=True, exist_ok=False)
    else:
        work = Path(tempfile.mkdtemp(prefix=f'dn2-{args.target.lower()}-'))
    print(f'Private build directory: {work}', flush=True)
    source = work/'source'
    count = materialize(ROOT, source, profile)
    bank = work/'sample-bank.bin'
    bank.write_bytes(silent_bank())
    print(f'Generated silent bank; {count} exact stage identities rebased', flush=True)
    with (work/'rebuild.log').open('w') as log:
        result = subprocess.run([sys.executable, '-B', str(source/'build.py'), '--target', 'R011',
            '--dn2', str(private['dn2']), '--dt2', str(private['dt2']), '--sample-bank', str(bank),
            '--work', str(work/'rebuild'), '--out', str(work/'rebased-r011.syx'),
            '--toolchain', str(args.toolchain.resolve())], cwd=source,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'}, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f'Public-input rebuild failed; inspect {work/"rebuild.log"}')
    parent = work/'rebuild/usb-research/main'
    print('Staging R012 identity', flush=True)
    doc = stage_identity(parent, work/'main', source)
    main = work/'main'
    if args.target in ('R013', 'R014', 'R020'):
        print('Adding explicit sample-storage setup', flush=True)
        workspace = work/'rebuild/usb-research'
        for path in (source/'port/sample-storage/tree').rglob('*'):
            if path.is_file():
                destination = workspace/path.relative_to(source/'port/sample-storage/tree')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE':'1',
               'PYTHONPATH':os.pathsep.join(map(str, [source/'research/audits',
                    source/'port/dsp/support', source/'port/tools/dnfw/src']))}
        with (work/'sample-storage.log').open('w') as log:
            subprocess.run([sys.executable, '-B',
                str(workspace/'scripts/build_dn2_sample_storage_setup.py'),
                '--parent', str(main), '--out', str(work/'sample-storage')],
                cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        main = work/'sample-storage'
        doc = json.loads((main/'build-receipt.json').read_text())
    if args.target in ('R014', 'R020'):
        print('Adding checked sampler control fixes', flush=True)
        for path in (source/'port/sampler-fixes/tree').rglob('*'):
            if path.is_file():
                destination = workspace/path.relative_to(source/'port/sampler-fixes/tree')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
        # Callback equivalence checks read only the already extracted official MAINs.
        for family, relative in (
                ('dn2-1.11', 'firmware/dn2-1.11/section_3_MAIN_OS.bin'),
                ('dt2-1.16', 'output/dn2-research/dt2-donor-main/section_3_MAIN_OS.bin/section_3_MAIN_OS.bin')):
            destination = workspace/relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(work/'rebuild/main/firmware'/family/'section_3_MAIN_OS.bin', destination)
        previous = main/'expanded'
        for label, script, flag in (
                ('func-snapping', 'build_dn2_sampler_func_snapping.py', '--parent'),
                ('ui-actions', 'build_dn2_sampler_ui_actions.py', '--parent'),
                ('slice-isolation', 'build_dn2_slice_frame_isolation.py', '--input')):
            destination = work/label
            with (work/(label+'.log')).open('w') as log:
                subprocess.run([sys.executable, '-B', str(workspace/'scripts'/script),
                    flag, str(previous), '--out', str(destination)], cwd=workspace,
                    env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            previous = destination
        with (work/'sampler-fixes.log').open('w') as log:
            subprocess.run([sys.executable, '-B',
                str(workspace/'scripts/build_dn2_sampler_fixes_r014.py'),
                '--parent', str(main), '--patched', str(previous), '--out', str(work/'sampler-fixes')],
                cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        main = work/'sampler-fixes'
        doc = json.loads((main/'build-receipt.json').read_text())
    dsp = work/'rebuild/usb-research/dsp/section_7.bin'
    if args.target == 'R020':
        for revision, script in (
                ('r015', 'build_dn2_audit_fixes_r015.py'),
                ('r016', 'build_dn2_function_fixes_r016.py'),
                ('r017', 'build_dn2_manual_fixes_r017.py'),
                ('r018', 'build_dn2_manual_fixes_r018.py'),
                ('r019', 'build_dn2_emulator_fixes_r019.py'),
                ('r020', 'build_dn2_cold_boot_guard_r020.py')):
            print(f'Applying checked {revision.upper()} changes', flush=True)
            destination = work/'revisions'/revision
            with (work/(revision+'.log')).open('w') as log:
                subprocess.run([sys.executable, '-B', str(workspace/'scripts'/script),
                    '--parent', str(main), '--out', str(destination)], cwd=workspace,
                    env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            main = destination
        dsp_env = {**env, 'DIGIKIT':paths['digikit'], 'SELAS':paths['selas'],
                   'DSP_RELEASE_SELAS':paths['selas']}
        for revision, script in (('r017', 'r017_dsp_rebind.py'),
                                 ('r018', 'r018_dsp_stretch.py')):
            destination = work/'revisions'/revision/'dsp'
            arguments = (['--parent', str(dsp), '--out', str(destination)]
                         if revision == 'r017' else [str(dsp), str(destination)])
            with (work/(revision+'-dsp.log')).open('w') as log:
                subprocess.run([sys.executable, '-B', str(workspace/'scripts'/script),
                    *arguments], cwd=workspace, env=dsp_env, stdout=log,
                    stderr=subprocess.STDOUT, check=True)
            dsp = destination/'section_7.bin'
        doc = json.loads((main/'build-receipt.json').read_text())
    expected = release['outputs']
    for path, digest in ((main/'main-os.bin', expected['main_sha256']),
                         (main/'runtime.bin', expected['runtime_sha256']),
                         (main/'expanded/main-os.bin', expected['expanded_main_sha256']),
                         (dsp, expected['dsp_sha256'])):
        if SHA(path.read_bytes()) != digest:
            raise ValueError(f'{args.target} output hash mismatch: {path}')
    result = work/f'{args.target}.syx'
    with (work/'packaging.log').open('w') as log:
        subprocess.run([paths['container_tool'], '-i', str(private['dn2']),
                        '-c', '3', str(main/'main-os.bin'), '-c', '7', str(dsp),
                        '-o', str(result)], stdout=log, stderr=subprocess.STDOUT, check=True)
    verify(result, {'bytes':expected['sysex_bytes'], 'sha256':expected['sysex_sha256']}, f'{args.target} output')
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('xb') as target, result.open('rb') as original:
        shutil.copyfileobj(original, target)
    (work/'rebuild.json').write_text(json.dumps(dict(build=args.target,
        official_inputs={name:SHA(path.read_bytes()) for name,path in private.items()},
        generated_bank_sha256=SHA(bank.read_bytes()), main_sha256=doc['main_sha256'],
        dsp_sha256=expected['dsp_sha256'], sysex_sha256=expected['sysex_sha256'],
        hardware_access=False, private_sample_bank_required=False), indent=2)+'\n')
    print(f'Exact {args.target} verified: {out}\nSHA-256: {expected["sysex_sha256"]}')
