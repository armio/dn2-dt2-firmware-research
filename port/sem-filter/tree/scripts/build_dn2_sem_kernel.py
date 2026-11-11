"""Compile the Faust-derived SEM kernel into a bounded, standalone SHARC section."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src/sem_filter'
TOOLS = ROOT / 'firmware/ghidra/oneshot-proof/v6-source/toolchain/selache-2b26d3b/target/release'
sys.path.insert(0, str(ROOT / 'firmware/ghidra/oneshot-proof/v7-source/src'))
from dnfw.image import sharc_object as O

CODE, PHYSICAL, LIMIT = 0xbdb000, 0x200b6000, 0x200c4000
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def build(out, tools=TOOLS):
    out.mkdir(parents=True, exist_ok=True)
    for name in ('selcc', 'selas', 'seld'):
        if not (tools / name).is_file():
            raise ValueError(f'Build the pinned selache tool first: {tools / name}')
    def run(args):
        proc = subprocess.run([str(x) for x in args], capture_output=True, text=True)
        if proc.returncode:
            raise RuntimeError(proc.stdout + proc.stderr)
    # One translation unit lets the pinned compiler resolve the adapter and
    # kernel together, without importing a runtime or libm implementation.
    combined = out/'sem-all.c'
    combined.write_text('#include "sem_filter.c"\n#include "sem_dn2.c"\n')
    assembly = out / 'sem.asm'
    run([tools/'selcc', '-proc', 'ADSP-21569', '-O', '-DSEM_FILTER_NO_LIBM',
         '-I', SRC, '-S', '-o', assembly, combined])
    # Resolve PRM 4-14's conservative branch runway rule literally. Keep the
    # SW address/link ABI, but emit only uncompressed 48-bit instructions and
    # leave twelve valid instructions after the final return's delay slots.
    source = assembly.read_text()
    # Keep the compiler's coefficient/initialization wrapper, replacing only
    # its spill-heavy sample recurrence with the equivalent scalar hot loop.
    fast_source = SRC/'sem_filter_process.asm'
    source, replaced = re.subn(r'\.GLOBAL sem_filter_process\.;\nsem_filter_process\.:.*?(?=normalized\.:)',
                              lambda _: fast_source.read_text()+'\n', source, flags=re.S)
    if replaced != 1:
        raise ValueError('expected one compiler process body before normalized helper')
    if source.count('.ENDSEG;') != 1:
        raise ValueError('unexpected compiler code-section termination')
    # This selas revision implements RFRAME only through its VISA compressor;
    # the uncompressed placeholder is NOP. Lower the compiler's two return
    # delay slots explicitly without adding a slot or altering return timing.
    frame_pair = '    RFRAME;\n    NOP;'
    frame_count = source.count(frame_pair)
    if not frame_count or source.count('RFRAME;') != frame_count:
        raise ValueError('unexpected compiler RFRAME return delay slots')
    source = source.replace(frame_pair, '    I7=I6;\n    I6=DM (0,I6);')
    source = '.NOCOMPRESS;\n' + source.replace('.ENDSEG;', '    NOP;\n'*12+'.ENDSEG;')
    lines, names = [], []
    for line in source.splitlines():
        clean = line.split('//', 1)[0].strip()
        if clean.endswith(';') and not clean.startswith('.') and not clean.endswith(':'):
            name = f'sem_audit_{len(names):04d}.'
            names.append(name)
            lines.extend((f'.GLOBAL {name};', f'{name}:'))
        lines.append(line)
    annotated = out / 'sem-bounded.asm'
    annotated.write_text('\n'.join(lines) + '\n')
    obj, elf = out/'sem.doj', out/'sem.dxe'
    run([tools/'selas', '-proc', 'ADSP-21569', '-o', obj, annotated])
    ldf = out/'sem.ldf'
    ldf.write_text(f'''ARCHITECTURE(ADSP-21569)
MEMORY {{ sem_memory {{ TYPE(BW RAM) START({PHYSICAL:#x}) END({LIMIT-1:#x}) WIDTH(8) }} }}
PROCESSOR core0 {{
 OUTPUT($COMMAND_LINE_OUTPUT_FILE)
 ENTRY(sem_filter_process.)
 SECTIONS {{ sem_code SW {{ INPUT_SECTIONS($COMMAND_LINE_OBJECTS(seg_swco)) }} > sem_memory }}
}}
''')
    run([tools/'seld', '-proc', 'ADSP-21569', '-T', ldf, '-o', elf, obj])
    linked = elf.read_bytes()
    symbols = O.symbols(linked)
    code = O.load_bytes(O.code(linked, 'sem_code'))
    starts = [symbols[name] for name in names]
    if (not starts or starts[0] != CODE or starts != sorted(set(starts)) or
            PHYSICAL+len(code) > LIMIT):
        raise ValueError('Compiler section/producer boundaries exceed reservation')
    widths = [2*(b-a) for a,b in zip(starts, starts[1:]+[CODE+len(code)//2])]
    if any(size != 6 for size in widths):
        raise ValueError('SEM code must use uncompressed 48-bit instruction widths')
    # Linked code must carry no unresolved symbol other than ELF symbol zero.
    shoff = struct.unpack_from('<I', linked, 0x20)[0]
    entsize, count = struct.unpack_from('<HH', linked, 0x2e)
    for i in range(count):
        h = struct.unpack_from('<10I', linked, shoff+i*entsize)
        if h[1] == O.SHT_SYMTAB:
            for at in range(h[4]+16, h[4]+h[5], 16):
                if struct.unpack_from('<H', linked, at+14)[0] == 0:
                    raise ValueError('Unresolved linked symbol')
    (out/'kernel.bin').write_bytes(code)
    receipt = dict(model='Faust ve.oberheim / Eric Tarr / STK-4.3',
        code=hex(CODE), physical=hex(PHYSICAL), limit=hex(LIMIT), code_bytes=len(code),
        code_sha256=sha(code), state_bytes=60, native_slot_bytes=128,
        symbols={name:hex(value) for name,value in symbols.items()
                 if name.startswith(('sem_filter_', 'sem_dn2_')) and name.endswith('.')},
        instruction_offsets=[2*(pc-CODE) for pc in starts],
        instruction_contract=dict(uncompressed_bits=48,trailing_guard_instructions=12,
                                  explicit_frame_restores=frame_count,
                                  reference='SHARC+ PRM rev1.5,4-14'),
        source_sha256={p.name:sha(p.read_bytes()) for p in
                       (SRC/'sem_filter.c',SRC/'sem_filter.h',SRC/'sem_dn2.c',SRC/'sem_dn2.h',fast_source)},
        tools_sha256={name:sha((tools/name).read_bytes()) for name in ('selcc','selas','seld')},
        limits=['Not a firmware image; no native dispatch hooks installed here.',
                'Compilation and placement do not establish silicon timing or ABI conformance.'])
    (out/'kernel.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--tools', type=Path, default=TOOLS)
    args = parser.parse_args()
    result = build(args.out.resolve(), args.tools.resolve())
    print(json.dumps({key:result[key] for key in ('code','code_bytes','code_sha256','symbols')}))
