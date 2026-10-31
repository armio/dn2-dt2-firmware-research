#!/usr/bin/env python3
"""Restore DT2's unconditional fresh-note decimator reset for paired samplers."""
from pathlib import Path
import argparse, collections, json
import build_dt2_cursor_release_floor_fix as P
C, B, A, O = P.C, P.B, P.A, P.O
BASE = C.ROOT/'output/dn2-research/dt2-dsp-cursor-release-floor-20261010/section_7.bin'
SHA = 'f4e6c5f84e2ad7dfd99532a02d13bc1c6cbe19d16122f8d740c1a44ab7b8fc6e'
CODE, RESET = 0xbf7400, 0xbf7500
ARM = 0xbcb03f
SITES = (0xbcadb5, 0xbcb6e3)


def build(out):
    raw=BASE.read_bytes(); assert C.SHA(raw)==SHA
    doc=json.loads((BASE.parent/'build-receipt.json').read_text())
    k=C.M.Digikit(C.SRC/'toolchains/digikit'); k.ldr.L2_BYTE_LIMIT=0x20100000
    import sharcfn
    m=B.decode_view(k,raw); donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
    assert C.SHA(C.DONOR.read_bytes())==C.DONOR_SHA
    out.mkdir(parents=True,exist_ok=False)
    # ARM has no stack locals. Keep every native state write in its original
    # order, omitting only return-pointer load/RETURN/RFRAME. The native reset
    # can then return through the unchanged original linked caller frame.
    pieces=((0x1c4eaf,0x1c4ec2),(0x1c4ec4,0x1c4eca),(0x1c4ecc,0x1c4ece))
    arm=b''.join(donor.read_sw(a,2*(z-a)) for a,z in pieces)
    assert m.read_sw(ARM,64)==donor.read_sw(0x1c4eaf,64)
    tail='''.SECTION/PM seg_pmco;
.GLOBAL reset_tail.;
reset_tail.:
      R0 = 0x104;
      R4 = R4 + R0;
      JUMP 0xbf7500;
'''
    asm=out/'reset-tail.asm';asm.write_text(tail)
    be,tailoffs=A._selas(asm,out); code=arm+O.load_bytes(be)
    assert CODE+len(code)//2<RESET
    reset=donor.read_sw(0xb80105,2*(0xb8015b-0xb80105))
    offsets=[]; listing=[]; dest=CODE
    for a,z in pieces:
        pc=a
        while pc<z:
            ins=k.st.decode_at(donor,None,pc)
            offsets.append(2*(dest-CODE))
            listing.append(f'{dest:08x} <- {pc:08x} '+sharcfn.render_instruction(pc,ins,donor,set(),collections.Counter(),[])[0])
            dest+=ins.length_bytes//2;pc+=ins.length_bytes//2
        assert pc==z
    offsets.extend(len(arm)+x for x in tailoffs)
    resetoffs=[]; resetlisting=[]; pc=0xb80105
    while pc<0xb8015b:
        ins=k.st.decode_at(donor,None,pc)
        assert ins.type_name in ('5b_move','19a_scaled','15b','17b','19a','16b','18a','3b','21c','9b_abs','25c_rframe'),ins
        assert not any(x.startswith(('addr','rel')) for x in ins.fields),ins
        resetoffs.append(2*(pc-0xb80105))
        resetlisting.append(f'{RESET+pc-0xb80105:08x} <- {pc:08x} '+sharcfn.render_instruction(pc,ins,donor,set(),collections.Counter(),[])[0])
        pc+=ins.length_bytes//2
    assert pc==0xb8015b
    (out/'native-decimator-reset.asm').write_text('\n'.join(resetlisting)+'\n')
    (out/'native-arm-wrapper.asm').write_text('\n'.join(listing)+'\n'+tail)
    evidence=[];pc=0x1c657b
    while pc<0x1c65ba:
        ins=k.st.decode_at(donor,None,pc)
        evidence.append(f'{pc:08x} '+sharcfn.render_instruction(pc,ins,donor,set(),collections.Counter(),[])[0]);pc+=ins.length_bytes//2
    (out/'donor-note-start.asm').write_text('\n'.join(evidence)+'\n')
    image=bytearray(raw);patches=[]
    for pc in SITES:
        before=m.read_sw(pc,6); assert before==C.S.to_bytes(0x180400000000|ARM)
        after=C.S.to_bytes(0x180400000000|CODE)
        C.B.write_span(image,C.S.code_address(pc,window='l2'),after)
        patches.append(dict(pc=hex(pc),before=before.hex(),after=after.hex(),delay_slots_unchanged=True))
    blocks=[]
    for pc,body in ((CODE,code),(RESET,reset)):
        at=C.S.code_address(pc,window='l2')
        assert not any(a<at+len(body) and at<a+len(v) for a,v in (*C.B.load_regions(raw),*blocks))
        blocks.append((at,body))
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,v) for a,v in blocks))
    walk=C.B.walk(result); first,last=walk.blocks[7],walk.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['sampler_start_fix']=dict(base=str(BASE),base_sha256=SHA,code=hex(CODE),code_bytes=len(code),instruction_offsets=offsets,
        reset=dict(donor='0xb80105',end='0xb8015b',target=hex(RESET),bytes=len(reset),sha256=C.SHA(reset),instruction_offsets=resetoffs,exact_native_bytes=True),
        patches=patches,arm_pieces=[dict(start=hex(a),end=hex(z)) for a,z in pieces],
        contract='Both existing fresh-note ARM calls now reproduce all native ARM state writes, then tail-call the exact DT2 decimator-history reset at record+0x104. Held-note paths, note gates, fade flags, preview, allocation, renderer and stock audio paths are unchanged.',
        native_evidence='DT2 0x1c6582 calls ARM; 0x1c65b3 unconditionally calls B80105(record+0x104) inside that same start preamble. Conditional fade/zero-cross settings between these calls do not guard the reset.',
        limitations=['This repairs a confirmed port omission; it does not establish the cause of the reported hardware clicks.','Donor conditional fade/zero-cross policy is not changed.','Hardware timing/cache behavior is not modeled.'])
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),wrapper_bytes=len(code),reset_bytes=len(reset))))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
