#!/usr/bin/env python3
"""Link the original SampleBrowserPopupMenuView with native DN2 UI services."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B


def build(out):
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    bindings={};evidence=[]
    earlier=json.loads((B.M.OUT/'map.json').read_text())
    assert B.T.SHA(native)==earlier['recipient_sha256']
    for row in earlier['functions']:
        if len(row.get('dn2_twins',[]))==1:
            bindings[int(row['donor'],16)]=int(row['dn2_twins'][0],16)
        for pair in row.get('operands',[]):
            old,new=int(pair['donor'],16),int(pair['dn2'],16)
            if old in bindings:assert bindings[old]==new
            bindings[old]=new
    # Full unchanged instruction bodies establish shared widget/timer services
    # and their associated vtables/globals, not guessed address deltas.
    for entry in (0x40090168,0x40110344,0x40111888,0x40023d12,0x401155b6):
        end,rows=B.M.function(donor,entry);blob=donor[entry-B.BASE:end-B.BASE]
        refs=list(B.M.operands(rows));mask=bytearray(b'\1'*len(blob))
        for operand,_,_,_ in refs:mask[operand-entry:operand-entry+4]=bytes(4)
        pattern=b''.join(re.escape(bytes([v])) if keep else b'.' for v,keep in zip(blob,mask))
        hits=[B.BASE+m.start() for m in re.finditer(pattern,native,re.S) if m.start()%2==0]
        assert len(hits)==1,(hex(entry),hits)
        dest=hits[0];bindings[entry]=dest;pairs=[]
        for operand,target,_,_ in refs:
            value=struct.unpack_from('>I',native,dest-B.BASE+operand-entry)[0]
            if target in bindings:assert bindings[target]==value,(hex(target),hex(value))
            bindings[target]=value;pairs.append(dict(donor=hex(target),dn2=hex(value)))
        evidence.append(dict(donor=hex(entry),end=hex(end),dn2=hex(dest),operands=pairs))
    # Adjacent original StringArg/font initialization blocks independently
    # establish the popup's selected-font pointer global.
    old=donor[0x401d0eb6-B.BASE:0x401d0ece-B.BASE]
    new=native[0x401b9d4c-B.BASE:0x401b9d64-B.BASE]
    assert old==bytes.fromhex('203c4021cb5823c044d2e6ec203c402a913423c044d2e6f0')
    assert new==bytes.fromhex('203c4020652423c044507ed8203c40293c6423c044507edc')
    bindings[0x44d2e6f0]=0x44507edc
    # GNU COW string characters follow their12-byte shared header. The header
    # itself is anchored by the complete native destructor twin in map.json.
    assert bindings[0x44f37238]==0x44647a68
    bindings[0x44f37244]=bindings[0x44f37238]+12
    L.INPUT=B.T.ROOT/'output/dn2-research/dt2-directory-model-20261009'
    L.SHA='c99774323c0839da11c8e2fe33dff269c97bc3818bbe76fa57ad39b9ed6b2534'
    L.COMPONENT='browser_popup';L.DIRECTORY_AUX=False;L.EXTRA_BINDINGS=bindings
    L.INFER_NATIVE_LIBRARY_OPERANDS=True
    assert donor[0x4022989d-B.BASE:0x4022989f-B.BASE]==b'\x1b\0'
    L.EXTRA_DATA={0x4022989d:b'\x1b\0'}
    L.CODE=[('popup',0x400232e0,0x40023e84),('popup_lifetime',0x4019b324,0x4019b426)]
    L.DATA=[('popup_types',0x401eed94,0x401eeef0)]
    L.METHODS={'constructor':0x40023370,'destroy':0x4019b324,'draw':0x400236b0,
               'event':0x40023b34,'tick':0x40023d12,'content_x':0x40023338}
    L.build(out)
    path=out/'build-receipt.json';doc=json.loads(path.read_text())
    doc['browser_popup']['native_anchors']=evidence
    doc['browser_popup']['font_pointer_binding']={'donor':'0x44d2e6f0','dn2':'0x44507edc','basis':'paired complete24B initialization blocks'}
    path.write_text(json.dumps(doc,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    build(parser.parse_args().output)
