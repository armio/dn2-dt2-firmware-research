#!/usr/bin/env python3
"""Gate the relocated right effects chain to DT2 sampler voices (R025 DSP).

The right lane's audio stages run only for voices whose machine word, the one the
output stage reads, is a sampler (5..10). Setters, AMP and event cleanup keep
running on all 16 voices. The stock left chain is not touched.
"""
import argparse
import json
import re
from pathlib import Path

import build_dn2_sem_dsp as SEM

C, A, O, B, AUDIT = SEM.C, SEM.A, SEM.O, SEM.B, SEM.AUDIT
PARENT_SHA = 'b5ba74131db8ec13250950296a21326b589971d8b7da5c54144f1b1be3564c29'   # R024 DSP
CODE, CODE_END = 0xbdac00, 0xbdb000     # free tail of the SEM adapter's L2 span; no block of the parent loads it
MASK = 0x805d9790                       # free zeroed word in the right hook's state block (0x805d9600..0x805d9804)
MACHINES = 0x25c520                     # per-voice machine words, 16 bits each; the output hook reads the same
SEM_RIGHT_ACTIVE = SEM.STATE+0x800+76   # 'active' word of a right-lane SEM slot; stride 128
HOOK_SITE, HOOK_RESUME = 0xbce94f, 0xbce952     # 'R4 = right engine' just before the right chain is called
FILTER_SITE = 0x1c9584                  # JUMP IF GE to the iteration update: the stock skip path
# native call site -> (callee, countdown register of its per-voice loop); voice v is at count 16 - v
CALLS = {0x1c9459: (0xb8251b, 'R15'), 0x1c94fd: (0xb80c39, 'R10'),
         0x1c959f: (0xb81368, 'R15'), 0x1c9b7a: (0xb81368, 'R15'),
         0x1c95b4: (0xb8265b, 'R15'), 0x1c9b8f: (0xb8265b, 'R15'),
         0x1c95c9: (0x1cdb56, 'R15'), 0x1c9935: (0x1cdb56, 'R15')}
right = SEM.right


def source():
    def label(name):
        return f'.GLOBAL {name};\n{name}:\n'
    s = '.SECTION/PM seg_pmco;\n.NOCOMPRESS;\n' + label('gate_mask.') + f'''      R3 = DM({MASK:#x});
      R2 = 0;
'''
    for v in range(16):
        done = f'gate_mask_{v}_done.'
        s += f'      R0 = DM({MACHINES+4*(v//2):#x});\n'
        if v % 2:
            s += '      R0 = LSHIFT R0 BY -16;\n'
        s += f'''      R1 = 0xffff;
      R0 = R0 AND R1;
      R1 = 5;
      COMP(R0, R1);
      IF LT JUMP 0x0; // -> {done}
      R1 = 11;
      COMP(R0, R1);
      IF GE JUMP 0x0; // -> {done}
      R2 = BSET R2 BY {16-v};
''' + label(done)
    # The stock trigger reset does not cover SEM. A slot that just became a sampler slot gets a fresh
    # right-lane SEM state, as on a slot with no history; its state was frozen while the slot was gated.
    s += f'''      DM({MASK:#x}) = R2;
      R3 = NOT R3;
      R3 = R2 AND R3;
      R0 = 0;
'''
    for v in range(16):
        done = f'gate_fresh_{v}_done.'
        s += f'''      BTST R3 BY {16-v};
      IF SZ JUMP 0x0; // -> {done}
      DM({SEM_RIGHT_ACTIVE+128*v:#x}) = R0;
''' + label(done)
    s += label('gate_mask_replay.') + f'''      NOP;
      JUMP {HOOK_RESUME:#x};
'''
    for callee, register in sorted(set(CALLS.values())):
        # Reached through the stock linked call: the caller's frame is already pushed.
        s += label(f'gate_{callee:x}.') + f'''      R0 = DM({MASK:#x});
      BTST R0 BY {register};
      IF NOT SZ JUMP {callee:#x};
      I12 = DM(M7, I6);
      JUMP (M14, I12) (DB);
      I7 = I6;
      I6 = DM(0, I6);
'''
    # The flags of the stock type compare are still valid at entry; R1 is reloaded by stock at 1C958E.
    s += label('gate_filter.') + f'''      IF GE JUMP {right(0x1c98b9):#x};
      R1 = DM({MASK:#x});
      BTST R1 BY R15;
      IF SZ JUMP {right(0x1c98b9):#x};
      JUMP {right(0x1c9587):#x};
''' + label('gate_prefetch_guard.') + '      NOP;\n'*12
    return s


def build(parent, out, ungated=()):
    raw = parent.read_bytes()
    doc = json.loads((parent.parent/'build-receipt.json').read_text())
    if C.SHA(raw) != PARENT_SHA or doc['section7_sha256'] != PARENT_SHA:
        raise ValueError('unexpected parent DSP')
    k = C.M.Digikit(C.SRC/'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    out.mkdir(parents=True, exist_ok=False)
    asm = out/'right-gate.asm'
    text = source()
    asm.write_text(text)
    _, offsets = A._selas(asm, out)
    labels = {name: CODE+v for name, v in O.symbols((out/'right-gate.doj').read_bytes()).items()}
    text = re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))', lambda m: m[1]+hex(labels[m[3]])+m[2], text)
    asm.write_text(text)
    be, again = A._selas(asm, out)
    if offsets != again:
        raise ValueError('unstable gate instruction widths')
    code = bytearray(O.load_bytes(be))
    if any(z-a != 6 for a, z in zip(offsets, offsets[1:]+[len(code)])):
        raise ValueError('gate code must use uncompressed 48-bit instruction widths')
    if CODE+len(code)//2 > CODE_END:
        raise ValueError('gate code exceeds its reservation')

    image, patches = bytearray(raw), []

    def patch(pc, expected, after, name):
        before = memory.read_sw(pc, len(expected))
        if before != expected:
            raise ValueError(f'unexpected {name} preimage at {pc:#x}: {before.hex()}')
        if len(after) != len(before):
            raise ValueError('patch changes instruction span')
        C.B.write_span(image, C.S.code_address(pc, window='l2'), after)
        patches.append(dict(name=name, pc=hex(pc), before=before.hex(), after=after.hex()))

    def jump(target):
        return C.S.to_bytes(0x063e00000000 | target)

    def replay(name, displaced):
        at = 2*(labels[name]-CODE)
        code[at:at+6] = displaced

    # Block hook: build the mask, then run the displaced 'R4 = right engine'.
    load_engine = C.S.to_bytes(0x0f0400000000 | SEM.RIGHT_ENGINE)
    replay('gate_mask_replay.', load_engine)
    patch(HOOK_SITE, load_engine, jump(labels['gate_mask.']), 'mask-before-right-chain')
    # Filter dispatch: the stock jump is PC-relative, so the stub carries an absolute one with the same condition.
    native = k.st.decode_at(memory, None, FILTER_SITE)
    fields = native.fields
    if native.type_name != '8a_rel' or FILTER_SITE+(fields['reladdr[23:16]'] << 16 | fields['reladdr[15:0]']) != 0x1c98b9:
        raise ValueError('unexpected stock filter-dispatch skip')
    skip = C.S.to_bytes(0x06 << 40 | fields['cond[4:0]'] << 33 | right(0x1c98b9))
    at = 2*(labels['gate_filter.']-CODE)
    if bytes(code[at:at+6]) != skip:
        raise ValueError('assembled skip does not carry the stock condition')
    if 'filter' not in ungated:
        patch(right(FILTER_SITE), memory.read_sw(FILTER_SITE, 6), jump(labels['gate_filter.']), 'filter-dispatch')
    # Effect calls: only the target changes; the right copy must still equal the stock call.
    for site, (callee, _) in sorted(CALLS.items()):
        stock = k.st.decode_at(memory, None, site)
        if C.S.get_field(stock.raw, 'addr24') != callee:
            raise ValueError(f'unexpected stock call target at {site:#x}')
        if f'{callee:x}' in ungated:
            continue
        patch(right(site), C.S.to_bytes(stock.raw),
              C.S.to_bytes(C.S.retarget(stock.raw, 'addr24', right(site), labels[f'gate_{callee:x}.'])),
              f'call-{callee:x}')

    at = C.S.code_address(CODE, window='l2')
    if any(b.target < at+len(code) and at < b.target+b.count for b in C.B.walk(raw).blocks):
        raise ValueError('gate code overlaps loaded storage')
    if any(AUDIT.literals(raw, at, at+len(code))) or any(AUDIT.literals(raw, CODE, CODE+len(code)//2)):
        raise ValueError('preexisting references into the gate code span')
    if not any(b.target <= MASK and MASK+4 <= b.target+b.count for b in C.B.walk(raw).blocks):
        raise ValueError('mask word is outside the right hook state block')
    if memory.read(MASK, 4) != bytes(4) or any(AUDIT.literals(raw, MASK, MASK+4)):
        raise ValueError('mask word is not a free zeroed word')
    result = C.B.insert_before_final(bytes(image), C.B.block(at, bytes(code)))
    # Block 7 carries the stream distance to the final block; it moved by one inserted block.
    old = C.B.walk(raw)
    if old.blocks[7].argument != old.blocks[-1].offset-old.blocks[7].offset:
        raise ValueError('unexpected parent load-stream layout')
    walk = C.B.walk(result)
    first, last = walk.blocks[7], walk.blocks[-1]
    result = result[:first.offset]+C.B.block(first.target, flags=first.flags,
                                             argument=last.offset-first.offset)+result[first.end:]
    if not C.B.walk(result).complete:
        raise ValueError('incomplete DSP load stream')
    doc.update(section7_sha256=C.SHA(result), baseline_sha256=PARENT_SHA)
    doc['right_gate'] = dict(
        code=hex(CODE), code_bytes=len(code), instruction_offsets=offsets,
        labels={name: hex(v) for name, v in labels.items() if name.startswith('gate_')},
        patches=patches, mask=hex(MASK), machine_words=hex(MACHINES),
        sem_right_active=dict(base=hex(SEM_RIGHT_ACTIVE), stride=128, cleared='when a slot becomes a sampler slot'),
        calls={hex(right(site)): dict(native=hex(site), callee=hex(callee), counter=register)
               for site, (callee, register) in sorted(CALLS.items())},
        contract='Right-lane B8251B, DC blocker, pre/post effect calls and filter dispatch run only for voices '
                 'whose machine word is 5..10. Setters, AMP, event cleanup and the left chain are unchanged. '
                 'A slot that becomes a sampler slot starts with a fresh right-lane SEM state. '
                 'No status or mode register is written.',
        hardware_validated=False)
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    return doc['section7_sha256']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('parent', type=Path, help='R024 section_7.bin next to its build-receipt.json')
    parser.add_argument('out', type=Path)
    parser.add_argument('--ungated', default='', help='experiment: comma list of b8251b,b80c39,b81368,b8265b,1cdb56,filter to leave running')
    args = parser.parse_args()
    print(build(args.parent, args.out, tuple(filter(None, args.ungated.split(',')))))
