"""Append Faust SEM to the R022 DSP, preserving native filter arms 0..6."""
import argparse
import json
import re
import struct
from pathlib import Path

import build_dn2_right_process as P
import build_dn2_right_hooks as H
import build_dt2_dsp_startup_fix as B
import build_dt2_dsp_scratch_efficiency as AUDIT
import sem_register_contract

C, A, O = P.C, P.A, P.O
PARENT_SHA = '2b05931155bb097798e3f3926b1667f97629356baf78ee1c2efa294ce3a50c0e'
CUTOFF_TABLE_SHA = 'a7d139880e0bbe8e116e99fa5fe5a529cf28f7dccc1e886ded4543395f175258'
CODE, CODE_END = 0xbda800, 0xbdb000
STATE, STATE_END = 0x200c4000, 0x200c5000
STACK, STACK_END = 0x200c5000, 0x200c7000
SAVE, TABLE = 0x200c7000, 0x200c7400
RIGHT_ENGINE = 0x805c1000
REGS = H.REGS
# Keep the external contract at all99 registers. Only registers actually
# written by the scalar adapter/kernel need memory save traffic; the binary
# clobber census below rejects a new unsaved write before emitting firmware.
SAVED_REGS = [*(f'R{i}' for i in range(16)),
              *(f'I{i}' for i in (0,4,6,7,12)),
              *(f'M{i}' for i in (0,5,6,7,14)),
              *(f'L{i}' for i in (0,4,6,7,12)),
              'ASTATX','ASTATY','MODE1']


def right(pc):
    return 0xbcd000 + pc - 0x1c8ef1


def source(entry):
    def label(name):
        return f'.GLOBAL {name};\n{name}:\n'
    def jump(name, condition=''):
        return f'      {condition}JUMP 0x0; // -> {name}\n'
    def save():
        return ''.join(f'      DM({SAVE+4*REGS.index(reg):#x}) = {reg};\n'
                       for reg in SAVED_REGS if reg!='MODE1')
    def restore():
        # Loading B also changes I on hardware: restore bases first.
        order = [*(f'{bank}{i}' for bank in ('R','S','B','L','I','M') for i in range(16)),
                 'ASTATX', 'ASTATY']
        return ''.join(f'      {reg} = DM({SAVE+4*REGS.index(reg):#x});\n'
                       for reg in order if reg in SAVED_REGS)
    s = '.SECTION/PM seg_pmco;\n.NOCOMPRESS;\n'
    s += label('sem_unpack.') + f'''      DM({SAVE+0x1f0:#x}) = R1;
      R0 = M0;
      R1 = 6;
      COMPU(R0, R1);
'''+jump('sem_unpack_native.', 'IF LT ')+jump('sem_unpack_custom.', 'IF EQ ')+'''      R0 = 0;
'''+jump('sem_unpack_done.')+label('sem_unpack_native.')+'''      R0 = 0x11223344;
'''+jump('sem_unpack_finish.')+label('sem_unpack_custom.')+'''      R0 = 7;
'''+label('sem_unpack_done.')+'''      F8 = FLOAT R8;
      S0 = R0;
'''+label('sem_unpack_finish.')+f'''
      R1 = DM({SAVE+0x1f0:#x});
      JUMP 0x1c2c46;
'''
    # R3 is the native setter's voice index. I0 has advanced by record stride.
    # Previous native filter type is kept at I15-17; this matches native reset
    # semantics (type transition resets, ordinary note/parameter changes do not).
    s += label('sem_set.') + f'''      R0 = LSHIFT R3 BY 7;
      R1 = {STATE:#x};
      R2 = {RIGHT_ENGINE:#x};
      COMP(R4, R2);
'''+jump('sem_set_address.', 'IF NE ')+'''      R2 = 2048;
      R1 = R1 + R2;
'''+label('sem_set_address.')+'''      R0 = R0 + R1;
      I4 = R0;
      DM(16, I4) = R8;
      R0 = DM(-146, I0);
      DM(17, I4) = R0;
      R0 = DM(-148, I0);
      DM(18, I4) = R0;
      R2 = I4;
      I4 = I15;
      R0 = DM(-17, I4);
      I4 = R2;
      R1 = 7;
      COMP(R0, R1);
'''+jump('sem_set_done.', 'IF EQ ')+'''      R0 = 0;
      DM(19, I4) = R0;
'''+label('sem_set_done.')+f'''      R0 = I9;
      R1 = {RIGHT_ENGINE:#x};
      COMP(R0, R1);
      IF EQ JUMP {right(0x1c927e):#x};
      JUMP 0x1c927e;
'''
    # Save system mode before disabling PEy; paired data stores must never
    # overwrite the adjacent save slots when entered with SIMD enabled.
    s += label('sem_audio.') + f'''      DM({SAVE+4*REGS.index('MODE1'):#x}) = MODE1;
      BIT CLR MODE1 0x208000;
      BIT SET MODE1 0x10000;
      NOP;
      NOP;
'''+save()+'''
      R0 = 16;
      R0 = R0 - R15;
      R0 = LSHIFT R0 BY 7;
'''+f'''      R1 = {STATE:#x};
      R2 = I9;
      R4 = {RIGHT_ENGINE:#x};
      COMP(R2, R4);
'''+jump('sem_audio_address.', 'IF NE ')+'''      R2 = 2048;
      R1 = R1 + R2;
'''+label('sem_audio_address.')+'''      R4 = R0 + R1;
      R8 = I5;
      R12 = R9;
      M5 = 0;
      M6 = 1;
      M7 = -1;
      M14 = 1;
      L4 = 0;
      L6 = 0;
      L7 = 0;
      L12 = 0;
'''+f'''      I6 = {STACK_END-16:#x};
      I7 = {STACK_END-16:#x};
'''+H.E.P.V.linked(entry, 'sem_audio_return.')+f'''      R0 = I9;
      R1 = {RIGHT_ENGINE:#x};
      COMP(R0, R1);
'''+jump('sem_audio_resume_right.', 'IF EQ ')+restore()+f'''      MODE1 = DM({SAVE+4*REGS.index('MODE1'):#x});
      JUMP 0x1c98b9;
'''+label('sem_audio_resume_right.')+restore()+f'''      MODE1 = DM({SAVE+4*REGS.index('MODE1'):#x});
      JUMP {right(0x1c98b9):#x};
'''
    # A fresh engine must not inherit a prior project's custom filter history.
    # R0/R1/I4 are caller-scratch at this constructor entry; args stay intact.
    s += label('sem_init.') + '      R0 = 0;\n'
    s += ''.join(f'      DM({STATE+128*i+76:#x}) = R0;\n' for i in range(32))
    s += label('sem_init_replay.') + '''      R0 = 0x11223344;
      JUMP 0x1c8e1f;
'''
    # Keep a complete48-bit prefetch runway after the final unconditional jump.
    s += label('sem_prefetch_guard.') + '      NOP;\n'*12
    return s


def build(parent, kernel_folder, out):
    raw = parent.read_bytes()
    doc = json.loads((parent.parent/'build-receipt.json').read_text())
    if C.SHA(raw) != PARENT_SHA or doc['section7_sha256'] != PARENT_SHA:
        raise ValueError('unexpected parent DSP')
    kernel = (kernel_folder/'kernel.bin').read_bytes()
    kd = json.loads((kernel_folder/'kernel.json').read_text())
    if C.SHA(kernel) != kd['code_sha256'] or int(kd['physical'], 16) != 0x200b6000:
        raise ValueError('unexpected SEM kernel placement or hash')
    if len(kernel) > STATE-0x200b6000:
        raise ValueError('SEM kernel exceeds code reservation')
    k = C.M.Digikit(C.SRC/'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    if C.SHA(memory.read(0x2826d3c0,4096)) != CUTOFF_TABLE_SHA:
        raise ValueError('native effective-cutoff table changed')
    out.mkdir(parents=True, exist_ok=True)
    asm = out/'sem-adapter.asm'
    text = source(int(kd['symbols']['sem_dn2_process.'], 16))
    asm.write_text(text)
    _, offsets = A._selas(asm, out)
    labels = {name:CODE+v for name,v in O.symbols((out/'sem-adapter.doj').read_bytes()).items()}
    text = re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',
                  lambda m:m[1]+hex(labels[m[3]])+m[2], text)
    text = re.sub(r'(DM\(I7, M7\) = )0x0(; // return: (\w+\.))',
                  lambda m:m[1]+hex(labels[m[3]]-1)+m[2], text)
    asm.write_text(text)
    be, again = A._selas(asm, out)
    if offsets != again:
        raise ValueError('unstable adapter instruction widths')
    code = bytearray(O.load_bytes(be))
    if any(z-a != 6 for a,z in zip(offsets,offsets[1:]+[len(code)])):
        raise ValueError('SEM adapter must use uncompressed48-bit instruction widths')
    unpack_replay = 2*(labels['sem_unpack_native.']-CODE)
    code[unpack_replay:unpack_replay+6] = memory.read_sw(0x1c2c43,6)
    replay = 2*(labels['sem_init_replay.']-CODE)
    code[replay:replay+6] = memory.read_sw(0x1c8e1c,6)
    if CODE+len(code)//2 > CODE_END:
        raise ValueError('SEM adapter exceeds code reservation')
    system_fixes = []
    for offset in offsets:
        if offset+6 > len(code):
            continue
        value = C.S.to_value(code[offset:offset+6])
        if value>>40 not in (0x10,0x11):
            continue
        old = (value>>32)&0x7f
        if old in (0x70,0x73,0x74):
            new = {0x70:0x72,0x73:0x76,0x74:0x77}[old]
            code[offset:offset+6] = C.S.to_bytes((value&~(0x7f<<32))|(new<<32))
            system_fixes.append(dict(pc=hex(CODE+offset//2),before=old,after=new))
    if len(system_fixes) != 9:
        raise ValueError('unexpected SHARC+ status save/restore encodings')
    image = bytearray(raw)
    patches = []
    def patch(pc, expected, after, name):
        before = memory.read_sw(pc,len(expected))
        if before != expected:
            raise ValueError(f'unexpected {name} preimage at {pc:#x}: {before.hex()}')
        if len(after) != len(before):
            raise ValueError('patch changes instruction span')
        C.B.write_span(image,C.S.code_address(pc,window='l2' if pc>=0xb80000 else 'l1'),after)
        patches.append(dict(name=name,pc=hex(pc),before=before.hex(),after=after.hex()))
    patch(0x1c2c43,bytes.fromhex('3e4a0c2880a8'),
          C.S.to_bytes(0x063e00000000|labels['sem_unpack.']),'unpack-raw6')
    patch(0x1c8e1c,bytes.fromhex('8715fffff4ff'),
          C.S.to_bytes(0x063e00000000|labels['sem_init.']),'clear-on-engine-init')
    tables = []
    for lane, translate in enumerate((lambda v:v,right)):
        setter_at, process_at = TABLE+64*lane,TABLE+64*lane+32
        stock_set = [translate(v) for v in struct.unpack('<7I',memory.read(0x8052dba4,28))]
        stock_process = [translate(v) for v in struct.unpack('<7I',memory.read(0x8052dbc0,28))]
        tables += [(setter_at,struct.pack('<8I',*stock_set,labels['sem_set.'])),
                   (process_at,struct.pack('<8I',*stock_process,labels['sem_audio.']))]
        oldset = 0x8052dba4 if not lane else 0x805d9414
        oldprocess = 0x8052dbc0 if not lane else 0x805d9430
        patch(translate(0x1c917f),bytes.fromhex('8d0f0700'),bytes.fromhex('8d0f0800'),'setter-count')
        patch(translate(0x1c957e),bytes.fromhex('810f0700'),bytes.fromhex('810f0800'),'process-count')
        patch(translate(0x1c9188),C.S.to_bytes(0x0f1400000000|oldset),
              C.S.to_bytes(0x0f1400000000|setter_at),'setter-table')
        patch(translate(0x1c9587),C.S.to_bytes(0x0f1400000000|oldprocess),
              C.S.to_bytes(0x0f1400000000|process_at),'process-table')
    blocks = [(C.S.code_address(CODE,window='l2'),bytes(code)),
              (int(kd['physical'],16),kernel),(STATE,bytes(STATE_END-STATE)),
              (STACK,bytes(STACK_END-STACK)),(SAVE,bytes(0x200)),*tables]
    placed = list(C.B.load_regions(raw))
    audit = []
    for at,data in blocks:
        if any(b.target<at+len(data) and at<b.target+b.count for b in C.B.walk(raw).blocks):
            raise ValueError(f'SEM allocation overlaps loaded storage at {at:#x}')
        if any(a<at+len(data) and at<a+len(b) for a,b in placed):
            raise ValueError(f'SEM allocations overlap at {at:#x}')
        visa,pointers = AUDIT.literals(raw,at,at+len(data))
        classified = []
        # The two adjacent instructions produce an apparent 0x200b683f
        # across their parcel boundary. Neither instruction contains a pointer.
        if visa == [0x2009142a] and at==0x200b6000:
            expected = bytes.fromhex('3f6886bb0b203f6802c51021')
            if memory.read(0x20091426,12) != expected:
                raise ValueError('unclassified kernel-address literal')
            classified.append(dict(hit='0x2009142a',instructions='0xbc8a13,0xbc8a16',
                bytes=expected.hex(),meaning='R0=MAX(R0,R11),loadR7; R1=-R1,loadR10'))
            visa=[]
        if visa or pointers:
            raise ValueError(f'preexisting SEM storage references at {at:#x}: {visa,pointers}')
        audit.append(dict(start=hex(at),end=hex(at+len(data)),classified=classified))
        placed.append((at,data))
    for start,size in ((CODE,len(code)),(int(kd['code'],16),len(kernel))):
        if any(AUDIT.literals(raw,start,start+size//2)):
            raise ValueError('preexisting references into SEM program alias')
    result = C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    walk = C.B.walk(result)
    first,last = walk.blocks[7],walk.blocks[-1]
    result = result[:first.offset]+C.B.block(first.target,flags=first.flags,
              argument=last.offset-first.offset)+result[first.end:]
    if not C.B.walk(result).complete:
        raise ValueError('incomplete DSP load stream')
    doc.update(section7_sha256=C.SHA(result),baseline_sha256=PARENT_SHA)
    doc['sem_filter'] = dict(code=hex(CODE),code_bytes=len(code),instruction_offsets=offsets,
        labels={n:hex(v) for n,v in labels.items()},patches=patches,kernel=kd,
        state=dict(base=hex(STATE),bytes=STATE_END-STATE,stride=128,voices=16,lanes=2),
        stack=dict(base=hex(STACK),end=hex(STACK_END)),save=hex(SAVE),
        tables=[dict(base=hex(a),bytes=len(b)) for a,b in tables],
        preserved_registers=REGS,saved_registers=SAVED_REGS,
        sharc_plus_system_register_bindings=system_fixes,
        instruction_contract=dict(uncompressed_bits=48,trailing_guard_instructions=12,
            scalar_c_mode=dict(set_bits='0x10000',clear_bits='0x208000',
                               meaning='RND32 nearest,TRUNC off,PEYEN off;incomingMODE1 restored')),
        cutoff_table=dict(address='0x26d3c0',physical='0x2826d3c0',entries=1024,
            sha256=C.SHA(memory.read(0x2826d3c0,4096))),
        memory_audit=dict(regions=audit,loaded_or_fill_overlap=False,
            remaining_physical_or_code_alias_references=0,
            cache='Existing L2 reservation, cacheable (stock excludes only 0x200fa000-0x200fdfff); CPU-only code/state/stack; no DMA descriptors changed.',
            limitation='Loaded spans and classified literal closure cannot exclude every arbitrary computed writer.'),
        contract='Raw filter6 maps to internal7. Existing0..5/raw and0..6/internal remain native. '
                 'Each physical voice/channel owns128bytes; native effective cutoff includes envelope/keytrack. '
                 'Serialized audio-thread call; no DMA, USB, voice allocation or control-order changes.',
        hardware_validated=False)
    doc['sem_filter']['register_contract'] = sem_register_contract.audit(
        k, B.decode_view(k, result), doc['sem_filter'], kd, SAVED_REGS)
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    return doc['section7_sha256']


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('parent',type=Path);p.add_argument('kernel',type=Path);p.add_argument('out',type=Path)
    a=p.parse_args();print(build(a.parent,a.kernel,a.out))
