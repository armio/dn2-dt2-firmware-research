#!/usr/bin/env python3
"""Use DN2's existing serialized slice fields with original DT2 Sound methods."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-page-access-20261009'
SHA='651f9ee8e336df497653871ad0ef95a8abe7dd1b2d931247aa6d0a6d22ecb92d'
COUNT,MARKERS,SIZE=375,379,772

def build(out):
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    # Native initialization proves the stored layout, independently of the
    # coincidental difference between the two sound record sizes.
    proof={0x400e7e36:'42aa0177',0x400e7e3a:'45ea017b',0x400e7e48:'203c00000300'}
    for at,hx in proof.items():assert native[at-B.BASE:at-B.BASE+len(bytes.fromhex(hx))]==bytes.fromhex(hx)
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='slice_storage';L.LIMIT=0x47aa0000
    L.CODE=[('slice_sound',0x40050f32,0x400511b8),('list_link',0x401e3cd8,0x401e3cfe),
            ('slice_info_destroy',0x401aa06c,0x401aa078),('slice_info_delete',0x401aa108,0x401aa118),
            ('info_destroy',0x401a1ee0,0x401a1eec),('info_delete',0x401a1ffa,0x401a200a)]
    L.DATA=[('slice_info_vtable',0x401f50d4,0x401f50e4),('info_vtable',0x401f1c94,0x401f1ca4)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    L.EXTRA_BINDINGS={0x4011e8f0:0x40120264,0x4011e8fc:0x40120270,
                      0x401f3fe8:0x401dcd34,0x401f132c:0x401d8cbc}
    L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'empty':0x40050f32,'clear':0x40050f98,'count':0x4005101e,
               'to_list':0x4005104e,'set_list':0x400510f4}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());c=doc['runtime_copy']
    src,base=int(c['source'],16),int(c['destination'],16)
    raw=bytearray((out/'main-os.bin').read_bytes());payload=bytearray((out/'runtime.bin').read_bytes())
    component=doc['slice_storage'];span=next(s for s in component['spans'] if s['name']=='slice_sound')
    start=int(span['runtime'],16);patches=[]
    # These five methods access only slice fields through Sound::data().
    # Patch decoded displacement operands, never global integer occurrences.
    for pc,hx,mn,ops in B.M.S.disasm(donor,B.BASE,0x40050f32,0x400511b8):
        matches=list(re.finditer(r'\$(13c|140|144|148)\(a[0-5]\)',ops))
        for match in matches:
            width=len(bytes.fromhex(hx));assert width in (4,6),(hex(pc),ops)
            old=int(match[1],16);at=start+pc-0x40050f32+width-2
            assert payload[at-base:at-base+2]==struct.pack('>H',old)
            payload[at-base:at-base+2]=struct.pack('>H',old+59)
            patches.append(dict(donor=hex(pc),runtime=hex(at),old=old,new=old+59))
        if pc==0x400510a6:
            assert hx=='068100000140'
            at=start+pc-0x40050f32+2
            payload[at-base:at-base+4]=B.BE(MARKERS)
            patches.append(dict(donor=hex(pc),runtime=hex(at),old=320,new=MARKERS))
    assert len(patches)==12,len(patches)
    raw[src-B.BASE:src-B.BASE+len(payload)]=payload
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    component.update(layout_patches=patches,raw_sound_bytes=1163,count_offset=COUNT,markers_offset=MARKERS,
        marker_count=64,marker_stride=12,bytes=SIZE,
        native_initialization={hex(k):v for k,v in proof.items()},
        notification_typeinfo='0x401dcd34',
        limits=['Original routines now use native stored sound fields; editor call sites remain to connect.',
                'Existing native serialization includes these bytes; physical save/reload is not yet checked.'])
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),layout_patches=len(patches))))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
