#!/usr/bin/env python3
"""Port DT2 GRID's original linear/random lock assignment callback."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-dialogs-20261009'
SHA='5c22bd865a544b256e3086720952627b481d9876200d04bbf884181bb5d653be'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='grid_actions';L.LIMIT=0x47aa0000
    L.CODE=[('grid_assign_locks',0x4005f1d4,0x4005f328),
            ('grid_callback_manager',0x4005f3f8,0x4005f464),
            ('grid_parameter_snapshot',0x400509ec,0x40050a42),
            ('grid_snapshot_bounds',0x400d9e9c,0x400d9ea4)]
    L.DATA=[('grid_callback_type',0x401f6a38,0x401f6a40)];L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    binds={}
    for key in ('sample_manager','pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls','source_draw','source_browser','source_encoder','source_dialogs'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:binds[int(e['target'],16)]=int(e['binding'],16)
    binds[0x4005063e]=int(doc['source_browser']['methods']['source_browser_machine'],16)
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes();evidence=[]
    # Identical methods use the native pattern/lock owner and its storage
    # reader/writer, retaining DN2's 101-slot lock layout and notifications.
    for old in (0x400542ca,0x40053cf2,0x40054a6c,0x40054ad4,0x40053c7a,0x40053176,0x40042920,0x401521c4):
        end,rows=B.M.function(donor,old);blob=donor[old-B.BASE:end-B.BASE]
        refs=list(B.M.operands(rows));mask=bytearray(b'\1'*len(blob))
        for at,_,_,_ in refs:mask[at-old:at-old+4]=bytes(4)
        pattern=b''.join(re.escape(bytes([v])) if keep else b'.' for v,keep in zip(blob,mask))
        hits=[B.BASE+m.start() for m in re.finditer(pattern,native,re.S) if m.start()%2==0]
        assert len(hits)==1,(hex(old),hits)
        new=hits[0];pairs=[];binds[old]=new
        for at,target,_,_ in refs:
            dest=struct.unpack_from('>I',native,new-B.BASE+at-old)[0]
            binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest)))
        # External relative operands must refer to corresponding native peers.
        for at,hx,mn,ops in rows:
            m=re.search(r'\$([0-9a-f]{8})\(pc\)',ops)
            if m and not old<=int(m[1],16)<end:
                target=int(m[1],16);dest=target+new-old
                binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest),relative=True))
        evidence.append(dict(donor=hex(old),native=hex(new),bytes=end-old,operands=pairs))
    # Keep DT2's original ten-word snapshot (slots25..34): DN2's
    # identically shaped routine calls a different upper-bound getter (64),
    # which would overflow the callback's20-byte stack destination.
    assert donor[0x400d9e9c-B.BASE:0x400d9ea4-B.BASE]==bytes.fromhex('70194e7570224e75')
    # Native descriptor getter has the native table/ceiling. Caller literals
    # are translated below, so no donor ID is passed to this native getter.
    old,new,size=0x400d9ed8,0x400dbcc4,36
    x=bytearray(donor[old-B.BASE:old-B.BASE+size]);y=bytearray(native[new-B.BASE:new-B.BASE+size])
    assert x[6:10]==B.BE(275) and y[6:10]==B.BE(321)
    assert x[14:18]==B.BE(0x4020f18c) and y[14:18]==B.BE(0x401f7f94)
    x[6:10]=y[6:10]=bytes(4);x[14:18]=y[14:18]=bytes(4);assert x==y
    binds[old]=new
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'assign_locks':0x4005f1d4,'callback_manager':0x4005f3f8};L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());c=doc['runtime_copy'];base=int(c['destination'],16);src=int(c['source'],16)
    raw=bytearray((out/'main-os.bin').read_bytes());payload=bytearray((out/'runtime.bin').read_bytes())
    entry=int(doc['grid_actions']['methods']['assign_locks'],16);patches=[]
    for at,old,new,width in [(0x4005f212,242,326,2),(0x4005f21c,244,328,2),
                             (0x4005f23e,244,328,2),(0x4005f292,244,328,2),
                             (0x4005f224,0x4f314,0x4f358,4)]:
        off=entry+at-0x4005f1d4-base
        assert int.from_bytes(payload[off:off+width],'big')==old,(hex(at),payload[off:off+width].hex())
        payload[off:off+width]=new.to_bytes(width,'big')
        patches.append(dict(donor=hex(at),runtime=hex(base+off),old=old,new=new,width=width))
    raw[src-B.BASE:src-B.BASE+len(payload)]=payload
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    doc['grid_actions'].update(native_body_evidence=evidence,patches=patches,
        limits=['Callable original GRID action; Source parent wiring and hardware pattern playback pending.'])
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],assign_locks=hex(entry))))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
