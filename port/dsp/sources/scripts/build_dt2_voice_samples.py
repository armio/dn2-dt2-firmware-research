#!/usr/bin/env python3
"""Bind DN2 sampler voices to the received DT2 sample table.

Replaces the OSB1 proof seed with original DT2 sample binding and note arming.
Right-channel descriptors are retained per voice; stereo rendering is a later
integration step. No final firmware or SysEx is produced.
"""
from pathlib import Path
import argparse,json,re
import build_dt2_pcm_receiver as B
import build_dt2_sampler_frame_bridge as F
C,A,O=F.C,F.A,F.O
BASE=C.ROOT/'output/dn2-research/dt2-pcm-startup-20261009/section_7.bin'
BASE_SHA='2fee7062e0e1adcc12e94a81bc7d17487f0816d1a6565501b70cdb6e8075d2da'
CODE,BIND,ARM=0x172d00,0x173000,0x17303f
STATE,DESC,CACHE=0x2fa200,0x2fa220,0x2fa240
END=0x2fa380


def mapped(v,*,required=False):
    if 0x1c4e70<=v<0x1c4ecf:return BIND+v-0x1c4e70
    return B.mapped(v,required=required)


def linked(target,name):
    return f'''      CJUMP {target:#x} (DB);
      DM(I7, M7) = R2;
      DM(I7, M7) = 0x0; // return: {name}
.GLOBAL {name};
{name}:
'''


def source():
    s=f'''.SECTION/PM seg_pmco;
.GLOBAL native_sample_select.;
native_sample_select.:
      DM({STATE:#x}) = I6;
      DM({STATE+4:#x}) = I7;
      I6 = I7;
      R0 = I7;
      R1 = -64;
      R0 = R0 + R1;
      I7 = R0;
      // DN2 SAMP is the full unsigned word at frame+6, including all banks.
      R0 = DM(0x30dc9c);
      R1 = 6;
      R0 = R0 + R1;
      R1 = 0xfffffffc;
      R1 = R0 AND R1;
      I4 = R1;
      R4 = DM(0, I4);
      R1 = 2;
      R0 = R0 AND R1;
      R0 = LSHIFT R0 BY 3;
      R1 = 0;
      R0 = R1 - R0;
      R4 = LSHIFT R4 BY R0;
      R1 = 0xffff;
      R4 = R4 AND R1;
      DM(0x30dcb8) = R4;
      R1 = {DESC:#x};
'''+linked(B.mapped(0x1c3f78),'native_sample_lookup_done.')
    s+=f'''      // Retain both pointers, frame count, rate and stereo for this voice.
      R0 = DM(0x30dc94);
      R1 = 20;
      R0 = R0 * R1 (SSI);
      R1 = {CACHE:#x};
      R0 = R0 + R1;
      I5 = R0;
      I4 = {DESC:#x};
      R0 = DM(0, I4);
      DM(0, I5) = R0;
      R1 = DM(1, I4);
      DM(1, I5) = R1;
      R1 = DM(2, I4);
      DM(2, I5) = R1;
      R1 = DM(3, I4);
      DM(3, I5) = R1;
      R1 = DM(4, I4);
      R2 = 0xff;
      R1 = R1 AND R2;
      DM(4, I5) = R1;
      // A descriptor change rebinds native metadata without arming a note.
      // Original binding preserves phase and ACTIVE for valid sample lengths.
      I4 = DM(0x30dc98);
      R1 = DM(0, I4);
      COMP(R0, R1);
      IF NE JUMP 0x0; // -> native_sample_bind.
      R0 = DM({DESC+8:#x});
      R1 = DM(98, I4);
      COMP(R0, R1);
      IF NE JUMP 0x0; // -> native_sample_bind.
      R0 = DM({DESC+12:#x});
      R1 = DM(97, I4);
      COMP(R0, R1);
      IF NE JUMP 0x0; // -> native_sample_bind.
      R1 = DM(99, I4);
      R1 = PASS R1;
      IF EQ JUMP 0x0; // -> native_sample_note.
.GLOBAL native_sample_bind.;
native_sample_bind.:
      // Original ABI: R4=record, R8=PCM, stack=(frames low,high,rate).
      R0 = I7;
      R1 = -4;
      R0 = R0 + R1;
      I7 = R0;
      R0 = DM({DESC+12:#x});
      DM(I7, M7) = R0;
      DM(I7, M7) = 0;
      R0 = DM({DESC+8:#x});
      DM(I7, M7) = R0;
      R4 = DM(0x30dc98);
      R8 = DM({DESC:#x});
'''+linked(BIND,'native_sample_bound.')+f'''      R0 = I7;
      R1 = 16;
      R0 = R0 + R1;
      I7 = R0;
.GLOBAL native_sample_note.;
native_sample_note.:
      R0 = DM(0x30dce8);
      R0 = PASS R0;
      IF EQ JUMP 0x0; // -> native_sample_return.
      R4 = DM(0x30dc98);
'''+linked(ARM,'native_sample_armed.')+f'''.GLOBAL native_sample_return.;
native_sample_return.:
      I6 = DM({STATE:#x});
      I7 = DM({STATE+4:#x});
      JUMP 0x185a42;
'''
    return s


def build(out):
    out.mkdir(parents=True,exist_ok=False)
    base=BASE.read_bytes();assert C.SHA(base)==BASE_SHA
    asm=out/'voice-samples.asm';text=source();asm.write_text(text)
    be,offsets=A._selas(asm,out)
    labels={n:CODE+off for n,off in O.symbols((out/'voice-samples.doj').read_bytes()).items() if n.startswith('native_')}
    text=re.sub(r'(JUMP\s+)0x0(;\s*// -> (native_\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],text)
    text=re.sub(r'(DM\(I7, M7\) = )0x0(; // return: (native_\w+\.))',lambda m:m[1]+hex(labels[m[3]]-1)+m[2],text)
    asm.write_text(text);be,again=A._selas(asm,out);assert again==offsets
    code=O.load_bytes(be)
    assert CODE+len(code)//2<=BIND
    k=C.M.Digikit(C.SRC/'toolchains/digikit');m=k.ldr.LoadedMemory.from_stream(base)
    donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
    binding,relocs,listing=B.relocate(k,donor,0x1c4e70,0x1c4ecf,BIND,mapper=mapped)
    (out/'original-bind-arm.asm').write_text('\n'.join(listing)+'\n')
    patches=[];result=bytearray(base)
    for pc,old,target,purpose in (
        (0x185a38,0x100100310800,CODE,'Replace OSB1 presence/selection with received descriptors'),
        (0x185ac3,0x10080030dc9c,0x185c3d,'Skip proof integer seed; native bind/arm already ran'),
        (0x1715d4,0x062400171647,0x1715d7,'Remove proof length ceiling for five new Machines'),
        (0x16f81e,0x06240016f922,0x16f821,'Remove proof length ceiling for ONESHOT'),
    ):
        ins=k.st.decode_at(m,None,pc);assert ins.raw==old and ins.length_bytes==6,(hex(pc),hex(ins.raw))
        replacement=0x063e00000000|target
        C.B.write_span(result,C.S.code_address(pc),C.S.to_bytes(replacement))
        patches.append(dict(pc=hex(pc),before=hex(old),after=hex(replacement),purpose=purpose))
    blocks=[(C.S.code_address(CODE),code),(C.S.code_address(BIND),binding),
            (C.S.data_address(STATE),bytes(END-STATE))]
    placed=[]
    for at,b in blocks:
        assert 0x282e5000<=at<at+len(b)<=0x28300000
        assert not any(a<at+len(b) and at<a+len(v) for a,v in (*C.B.load_regions(base),*placed))
        placed.append((at,b))
    linked_image=C.B.insert_before_final(bytes(result),b''.join(C.B.block(a,b) for a,b in blocks))
    (out/'section_7.bin').write_bytes(linked_image)
    receipt=dict(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(linked_image),
                 code_bytes=len(code),bind_arm_bytes=len(binding),
                 entry=hex(CODE),bind=hex(BIND),arm=hex(ARM),state=hex(STATE),cache=hex(CACHE),
                 labels={n:hex(a) for n,a in labels.items()},patches=patches,bind_relocations=relocs,
                 flash_ready=False,remaining=['Stereo voice rendering (right descriptors retained)',
                                             'Original host allocator/loader/preview',
                                             'Source/SLICE UI and full firmware/hardware validation'])
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:receipt[k] for k in ('section7_sha256','code_bytes','bind_arm_bytes','labels')},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
