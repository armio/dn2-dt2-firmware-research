#!/usr/bin/env python3
"""Bind SampleManager's direct font descriptor to the matching native font."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
B=L.B


def build(folder,out):
    raw=bytearray((folder/'main-os.bin').read_bytes())
    doc=json.loads((folder/'build-receipt.json').read_text())
    assert B.T.SHA(raw)==doc['main_sha256']
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    old=donor[0x401d0eb6-B.BASE:0x401d0ece-B.BASE]
    new=native[0x401b9d4c-B.BASE:0x401b9d64-B.BASE]
    assert old==bytes.fromhex('203c4021cb5823c044d2e6ec203c402a913423c044d2e6f0')
    assert new==bytes.fromhex('203c4020652423c044507ed8203c40293c6423c044507edc')
    # Same Font header, character advances, bitmap offsets and bitmap planes.
    old_font,new_font=0x402a9134,0x40293c64
    x=donor[old_font-B.BASE:old_font-B.BASE+20]
    y=native[new_font-B.BASE:new_font-B.BASE+20]
    assert x[:8]==y[:8]
    for at in (8,12,16):
        assert struct.unpack_from('>I',x,at)[0]-old_font==struct.unpack_from('>I',y,at)[0]-new_font
    assert donor[old_font-B.BASE+20:0x402a96a0-B.BASE]==native[new_font-B.BASE+20:0x402941d0-B.BASE]
    c=doc['runtime_copy'];base=int(c['destination'],16);src=int(c['source'],16)-B.BASE
    patches=[]
    for edit in doc['sample_manager']['edits']:
        if edit.get('target')!=hex(old_font):continue
        site=int(edit['runtime'],16);before=int(edit['binding'],16);offset=src+site-base
        assert struct.unpack_from('>I',raw,offset)[0]==before
        assert before!=new_font,'Already corrected'
        struct.pack_into('>I',raw,offset,new_font)
        edit['binding']=hex(new_font)
        patches.append(dict(address=hex(site),donor_operand=edit['donor'],before=hex(before),after=hex(new_font)))
    assert len(patches)==3,patches
    marker=int(doc['dsp_transfer_wait']['methods']['transfer_identity'],16)
    marker_offset=src+marker-base
    assert struct.unpack_from('>I',raw,marker_offset)[0]==0x54314436
    struct.pack_into('>I',raw,marker_offset,0x54314437)
    payload=raw[src:src+c['bytes']]
    doc['sample_manager_font_fix']=dict(patches=patches,donor_font=hex(old_font),native_font=hex(new_font),
        identity=dict(address=hex(marker),before='0x54314436',after='0x54314437'),
        basis='Paired native font initialization and byte-identical complete character tables/bitmap planes',
        defect='Binary Font descriptor was resolved as an empty C string; loaded-slot annotation used adjacent code as font data.')
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    out.mkdir(parents=True,exist_ok=False)
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('bootstrap.S','fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((folder/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],sample_manager_font_fix=doc['sample_manager_font_fix']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.folder,a.out)
