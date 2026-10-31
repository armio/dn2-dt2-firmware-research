#!/usr/bin/env python3
"""Link DT2 analysis and detailed waveform RPCs 7/8 (offline component)."""
from pathlib import Path
import argparse,json,struct
import build_dt2_waveform_length as L
C,R,W=L.C,L.R,L.W
BASE=C.ROOT/'output/dn2-research/dt2-waveform-length-20261009/section_7.bin'
SHA='c2d217be0a905c11883b12becb54b1b1674976f85840858a30789074352a10e7'
SPANS=(('analysis',0x1c4440,0x1c4914,0x18e000),
       ('handlers',0x1c3db0,0x1c3ec7,0x18e500),
       ('division',0xb88dca,0xb88e04,0x18e700))
OLD_STATE,STATE,STATE_SIZE=0x82a00008,0x805dd000,0x1bc
HEAP,HEAP_SIZE=0x80a00008,0x2000000
TABLE,SCRATCH=0x31b500,0x31b600

def mapped(v,*,required=False):
    for _,a,z,to in SPANS:
        if a<=v<z:return to+v-a
    if OLD_STATE<=v<OLD_STATE+STATE_SIZE:return STATE+v-OLD_STATE
    if 0x2575c8<=v<0x2577c4:return SCRATCH+v-0x2575c8
    return L.mapped(v,required=required)

def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit')
    d=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes());n=k.ldr.LoadedMemory.from_stream(raw)
    blocks=[];records=[];listings={}
    for name,a,z,to in SPANS:
        body,bindings,listing=R.relocate(k,d,a,z,to,mapper=mapped)
        blocks.append((C.S.code_address(to),body));listings[name]=listing
        records.append(dict(name=name,donor=hex(a),end=hex(z),target=hex(to),bytes=len(body),bindings=bindings))
    wait=W.mapped(0x1c3c1d)
    table=[W.mapped(v) for v in (0x1c3c3e,0x1c3c4f,0x1c3c72)]+[wait]*3+[L.CODE,mapped(0x1c3db0),mapped(0x1c3e02)]
    blocks.extend([(C.S.data_address(TABLE),struct.pack('<9I',*table)),
                   (C.S.data_address(SCRATCH),bytes(508)),(STATE,bytes(STATE_SIZE))])
    regions=C.B.load_regions(raw)
    # This proves only load-image separation. Dynamic RAM ownership remains
    # a final-integration requirement; the original 32 MiB heap is not loaded.
    for addr,data in blocks:
        assert not any(a<addr+len(data) and addr<a+len(b) for a,b in regions),hex(addr)
        regions.append((addr,data))
    assert not any(a<HEAP+HEAP_SIZE and HEAP<a+len(b) for a,b in regions)
    image=bytearray(raw);patches=[]
    for pc,old,new in [(W.mapped(0x1c3c0f),7,9),(W.mapped(0x1c3c11),L.TABLE,TABLE)]:
        ins=k.st.decode_at(n,None,pc)
        if pc==W.mapped(0x1c3c0f):
            assert n.read_sw(pc,4)==struct.pack('<HH',0x0f8f,old)
            after=struct.pack('<HH',0x0f8f,new)
        else:
            assert C.S.get_field(ins.raw,'data32')==old
            after=C.S.to_bytes(C.S.retarget(ins.raw,'data32',pc,new))
        C.B.write_span(image,C.S.code_address(pc),after)
        patches.append(dict(pc=hex(pc),before=hex(old),after=hex(new)))
    image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    doc=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),spans=records,
        enabled_commands=[0,1,2,6,7,8],table=hex(TABLE),patches=patches,
        state=dict(address=hex(STATE),bytes=STATE_SIZE),
        analysis_heap=dict(address=hex(HEAP),bytes=HEAP_SIZE,placement='Original DT2 address, provisional offline placement; dynamic ownership unverified'),
        flash_ready=False,remaining=['Reserve analysis heap against native dynamic allocations and PCM pool',
            'RPC commands3..5 and9..10, complete firmware integration and hardware validation'])
    out.mkdir(parents=True,exist_ok=False)
    (out/'section_7.bin').write_bytes(image)
    for name,listing in listings.items():(out/(name+'.asm')).write_text('\n'.join(listing)+'\n')
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps({key:doc[key] for key in ('section7_sha256','enabled_commands','analysis_heap','flash_ready')},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
