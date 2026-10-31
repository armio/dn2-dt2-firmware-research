#!/usr/bin/env python3
"""Connect original DT2 waveform dispatch, task creation and IRQ notification.

Commands 0..2 are integrated here. Recording/sample-edit RPC commands 3..10
remain a later integration step; this research component is not flash ready.
"""
from pathlib import Path
import argparse,json,struct
import build_dt2_waveform_transport as T
C,R,W=T.C,T.R,T.W
BASE=C.ROOT/'output/dn2-research/dt2-waveform-transport-20261009/section_7.bin'
SHA='91174d105163cbe4fb105d64349ee7498ac17584a4e587b57fb16c4247786702'
SPANS=(('worker',0x1c3bf0,0x1c3c95,0x18c200),('create',0x1c3f57,0x1c3f78,0x18c2c0),
       ('request',0x1c7782,0x1c778a,0x18c2f0),('interrupt',0x1c7f16,0x1c7f45,0x18c300))
TABLE,NAME,HANDLE,SCRATCH=0x31b100,0x31b110,0x31b120,0x31b200
BOOT,SITE,CALLBACK=0x18c380,0x1ca81b,0x1ca72d
KERNEL={0xb8615d:0xb88839,0xb86765:0xb88e41,0xb86b1e:0xb891fa,
        0x1c9342:0x1cbac0,0x1c7f45:0x1ca6b7}


def mapped(v,*,required=False):
    for _,a,z,to in SPANS:
        if a<=v<z:return to+v-a
    for a,z,to in ((0x2577c4,0x2577d0,TABLE),(0x2577f0,0x257800,NAME),
                   (0x257800,0x257804,HANDLE),(0x256cc4,0x256dc4,SCRATCH)):
        if a<=v<z:return to+v-a
    if v in KERNEL:return KERNEL[v]
    if T.LO<=v<T.HI or T.OLD_STATE<=v<T.OLD_STATE+T.SIZE or v in T.BINDINGS:return T.mapped(v,required=required)
    return W.mapped(v,required=required)


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes());native=k.ldr.LoadedMemory.from_stream(raw)
    out.mkdir(parents=True,exist_ok=False);blocks=[];records=[]
    for name,a,z,to in SPANS:
        body,changes,listing=R.relocate(k,donor,a,z,to,mapper=mapped);body=bytearray(body)
        if name=='worker':
            offset=2*(0x1c3c0f-a);before=struct.unpack_from('<I',body,offset)[0]
            assert before==0x000b0f8f
            struct.pack_into('<H',body,offset+2,3)
        blocks.append((C.S.code_address(to),bytes(body)))
        records.append(dict(name=name,donor=hex(a),target=hex(to),bytes=len(body),bindings=changes))
        (out/(name+'.asm')).write_text('\n'.join(listing)+'\n')
    data=bytearray(0x200)
    struct.pack_into('<3I',data,0,*[mapped(a) for a in (0x1c3c3e,0x1c3c4f,0x1c3c72)])
    data[NAME-TABLE:NAME-TABLE+16]=donor.read(C.S.data_address(0x2577f0),16)
    blocks.append((C.S.data_address(TABLE),bytes(data)))
    # Compiler-linked calls retain the caller's frame, then tail-call the
    # original native GPIO initialization (whose callback operand is patched).
    boot=bytearray()
    for target in (T.mapped(0x1c7d9f),mapped(0x1c3f57)):
        pc=BOOT+len(boot)//2;call=bytearray(donor.read_sw(0x1c80b7,14))
        call[:6]=C.S.to_bytes(C.S.retarget(C.S.to_value(call[:6]),'addr24',pc,target))
        call[8:14]=C.S.to_bytes(C.S.retarget(C.S.to_value(call[8:14]),'data32',pc+4,pc+6))
        boot.extend(call)
    boot.extend(C.S.to_bytes(0x063e00000000|0x1ca6d9));blocks.append((C.S.code_address(BOOT),bytes(boot)))
    regions=C.B.load_regions(raw)
    for a,b in blocks:
        assert not any(x<a+len(b) and a<x+len(y) for x,y in regions),hex(a)
        regions.append((a,b))
    image=bytearray(raw);patches=[]
    for pc,field,old,new in ((SITE,'addr24',0x1ca6d9,BOOT),(CALLBACK,'data32',0x1ca6a7,mapped(0x1c7f16))):
        ins=k.st.decode_at(native,None,pc);assert C.S.get_field(ins.raw,field)==old
        code=C.S.to_bytes(C.S.retarget(ins.raw,field,pc,new));C.B.write_span(image,C.S.code_address(pc),code)
        patches.append(dict(pc=hex(pc),before=hex(old),after=hex(new)))
    image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    doc=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),spans=records,patches=patches,
        entries={n:hex(mapped(a)) for n,a in [('worker',0x1c3bf0),('create',0x1c3f57),('interrupt',0x1c7f16)]},
        startup=hex(BOOT),handle=hex(HANDLE),table=hex(TABLE),enabled_commands=[0,1,2],startup_hook=True,flash_ready=False,
        remaining=['Original RPC commands3..10 and their recording/sample-edit dependencies',
                   'ColdFire RPC/cache integration and audition', 'Hardware task/IRQ timing and full firmware integration'])
    (out/'section_7.bin').write_bytes(image);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps({n:doc[n] for n in ('section7_sha256','entries','enabled_commands')},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
