#!/usr/bin/env python3
"""Adapt the original DT2 sample restore ordering to DN2 kits and locks."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-reset-20261009'
SHA='4f4dbe8795f3d63cf9413af4e6a79a3b6ab874d042d16d75e963c783996dbf25'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_restore_order';L.LIMIT=0x47aa0000
    L.CODE=[('collect',0x4004e598,0x4004e8be)]
    L.DATA=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.DIRECTORY_AUX=False
    L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_SPANS=[];bindings={}
    for key in ('sample_loader','sample_allocator','sample_manager','waveform_events','source_events'):
        L.EXTRA_SPANS.extend(doc[key]['spans'])
        for e in doc[key]['edits']:bindings[int(e['target'],16)]=int(e['binding'],16)
    bindings.update({0x401360ac:0x40134490,0x401360f4:0x401344d8,
        0x4011e8f0:0x40120264,0x4011e8fc:0x40120270,
        0x401988a2:0x4018a97a,0x40041d24:0x4003e41a,0x40041d40:0x4003e436,
        0x4003f304:0x4003b2ea,0x4003f3ba:0x4003b3a0,0x40054a6c:0x4004f896,
        0x400d9ed8:0x400dbcc4,0x400e6172:0x400e7bc6,
        0x400405ce:int(doc['used_samples']['methods']['used_sample_lock'],16)})
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    for lo,hi,to in ((0x4003f304,0x4003f33a,0x4003b2ea),):
        assert donor[lo-B.BASE:hi-B.BASE]==native[to-B.BASE:to+hi-lo-B.BASE]
    twin=bytearray(donor[0x40041d40-B.BASE:0x40041d68-B.BASE])
    assert twin[0x1e:0x22]==B.BE(0x43d0);twin[0x1e:0x22]=B.BE(0x4414)
    assert twin==native[0x4003e436-B.BASE:0x4003e45e-B.BASE]
    L.EXTRA_BINDINGS=bindings;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.RESERVE_VENEERS=True;L.METHODS={'collect':0x4004e598};L.build(out)
    receipt=json.loads((out/'build-receipt.json').read_text());cfg=receipt['sample_restore_order']
    copy=receipt['runtime_copy'];base=int(copy['destination'],16)
    payload=bytearray((out/'runtime.bin').read_bytes());entry=int(cfg['methods']['collect'],16)
    edits=[]
    def patch(old,expected,new,why):
        at=entry+old-0x4004e598;off=at-base
        assert payload[off:off+len(expected)]==expected,(hex(old),payload[off:off+len(expected)].hex())
        assert len(expected)==len(new);payload[off:off+len(new)]=new
        edits.append(dict(donor=hex(old),runtime=hex(at),before=expected.hex(),after=new.hex(),why=why))
    # DN2 saved kits retain SAMP at raw-kit+0x80; each Sound is1163B.
    # Its Machine is raw-kit+0x112 and only5..10 are sample Machines.
    start,end=0x4004e61c,0x4004e64a
    source=f'''.text
.equ restore_skip,.+{0x4004e702-start}
 movea.l 0x30(%sp),%a0
 adda.l %d4,%a0
 mvz.b 0x112(%a0),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.w restore_skip
 mvs.w 0x80(%a0),%d3
 move.l %d3,%d0
 andi.l #127,%d0
 beq.w restore_skip
'''
    body=B.R.assemble(source,entry+start-0x4004e598,out,'restore-kit-access')
    assert len(body)<=end-start
    patch(start,donor[start-B.BASE:end-B.BASE],body+b'\x4e\x71'*((end-start-len(body))//2),'Native sampler-only kit access')
    patch(0x4004e704,B.BE(0x450),B.BE(0x48b),'Native Sound stride')
    patch(0x4004e70a,B.BE(0x4500),B.BE(0x48b0),'Native sixteen-track extent')
    patch(0x4004e5fe,b'\x00\xcd',b'\x00\x04','Native sample parameter slot')
    patch(0x4004e862,bytes.fromhex('206900284e90'),b'\x4e\xb9'+B.BE(int(doc['project_sample_active']['methods']['sample_project_settings_raw'],16)),
          'Resolve persisted sample identities through native companion')
    image=bytearray((out/'main-os.bin').read_bytes());src=int(copy['source'],16)-B.BASE
    image[src:src+len(payload)]=payload
    receipt.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    cfg.update(adaptations=edits,connected_to_restore=False,
        behavior='Original kit order, parameter-lock order, then other valid identities; native membership set deduplicates kit/final scan, while lock visits may repeat an existing slot.',
        limits=['Complete restore scheduler and boot/project-switch invocation remain to be connected.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=receipt['main_sha256'],collect=cfg['methods']['collect']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
