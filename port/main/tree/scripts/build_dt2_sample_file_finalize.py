#!/usr/bin/env python3
"""Port original DT2 file-identity hash finalization with heap scratch buffers."""
from pathlib import Path
import argparse,json,struct,tempfile
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-restore-lifecycle-20261009'
SHA='96c3376b4f2aaf54aae41d5c43f09092ff27e5bbbc8c4f2916eb179fa96f2d0e'
ENTRY=0x47f12000

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_file_finalize';L.LIMIT=0x47aa0000
    L.CODE=[('hash_file',0x4015af0c,0x4015b016),('read_unlocked',0x401582ee,0x4015832e)]
    L.DATA=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_DATA={}
    # These words replace the donor's two fixed32KiB scratch buffers. The four
    # PEA/LEA instructions are changed to load the allocated pointer below.
    L.EXTRA_STATE=[('hash_read_pointer',0x4066d8c0,0x4066d8c4),('hash_meta_pointer',0x406658c0,0x406658c4)]
    # Reuse the emitted guarded sector I/O targets from the existing native
    # metadata update routine; never pull in the donor's hardware driver.
    fn=L.D.mapping(INPUT/'fn_new_map.txt');image=(INPUT/'main-os.bin').read_bytes();ref=fn[0x4015ada6]
    c=next(c for c in doc['copies'] if int(c['destination'],16)<=ref<int(c['destination'],16)+c['bytes'])
    offset=int(c['source'],16)-B.BASE+ref-int(c['destination'],16)
    io={}
    for old,site in ((0x4012deda,0x4015add0),(0x4012e0c0,0x4015adf6)):
        at=offset+site-0x4015ada6;assert image[at:at+2]==b'\x4e\xb9'
        io[old]=int.from_bytes(image[at+2:at+6],'big')
    L.EXTRA_SPANS=[];L.EXTRA_BINDINGS={**io,0x4011e8f0:0x40120264,0x4011e8fc:0x40120270,0x43fa243a:0x43fa243a}
    L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    source='''.text
 lea -12(%sp),%sp
 movem.l %d2-%d3/%a2,(%sp)
 move.l 16(%sp),%d2
 tst.l 0x44f2bd68
 beq.s failed_unlocked
 pea 0x46f4deb0
 jsr 0x400015a0
 addq.l #4,%sp
 move.l #65536,-(%sp)
 jsr 0x4011e8f0
 addq.l #4,%sp
 tst.l %d0
 beq.s failed_locked
 move.l %d0,%a2
 move.l %d0,0x4066d8c0
 addi.l #32768,%d0
 move.l %d0,0x406658c0
 move.l %d2,-(%sp)
 jsr 0x4015af0c
 addq.l #4,%sp
 move.l %d0,%d3
 move.l %a2,-(%sp)
 jsr 0x4011e8fc
 addq.l #4,%sp
 clr.l 0x4066d8c0
 clr.l 0x406658c0
 bra.s unlock
failed_locked:
 moveq #-1,%d3
unlock:
 pea 0x46f4deb0
 jsr 0x400016d2
 addq.l #4,%sp
 move.l %d3,%d0
 bra.s done
failed_unlocked:
 moveq #-1,%d0
done:
 movem.l (%sp),%d2-%d3/%a2
 lea 12(%sp),%sp
 rts
 .balign 4
'''
    with tempfile.TemporaryDirectory(prefix='file-finalize-') as temp:
        L.EXTRA_CODE=[('finalize',ENTRY,B.R.assemble(source,ENTRY,Path(temp),'finalize'))]
    L.METHODS={'finalize':ENTRY,'hash_file':0x4015af0c};L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());cfg=doc['sample_file_finalize']
    base=int(doc['runtime_copy']['destination'],16);src=int(doc['runtime_copy']['source'],16)-B.BASE
    payload=bytearray((out/'runtime.bin').read_bytes());image=bytearray((out/'main-os.bin').read_bytes())
    runtime=int(cfg['methods']['hash_file'],16);patches=[]
    for old,before,after in ((0x4015af68,'4879','2f39'),(0x4015af7a,'4879','2f39'),
                             (0x4015af90,'4879','2f39'),(0x4015afc2,'41f9','2079')):
        at=runtime+old-0x4015af0c;offset=at-base
        assert payload[offset:offset+2]==bytes.fromhex(before)
        payload[offset:offset+2]=bytes.fromhex(after);patches.append(dict(donor=hex(old),runtime=hex(at),before=before,after=after))
    image[src:src+len(payload)]=payload
    cfg.update(pointer_load_patches=patches,scratch_bytes=65536,automatic_import_hook=False,
        limits=['Call after sample file write/close, before requesting its persistent identity.',
                'Native upload/import completion route still needs to invoke this method.'])
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload))
    (out/'runtime.bin').write_bytes(payload);(out/'main-os.bin').write_bytes(image)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],methods=cfg['methods']),indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);build(parser.parse_args().out)
