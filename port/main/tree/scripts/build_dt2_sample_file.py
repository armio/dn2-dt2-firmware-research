#!/usr/bin/env python3
"""Port original DT2 File ownership/write/close, including identity finalization."""
from pathlib import Path
import argparse,json,re,struct,tempfile
import build_dt2_directory_model as L
import build_dt2_waveform_events as W
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-file-finalize-20261009'
SHA='f90e89bea224755a7f702e15813c1b917c999cadbc1f3de28defd28d2a117376'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text());finalize=int(doc['sample_file_finalize']['methods']['finalize'],16)
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_file';L.LIMIT=0x47aa0000
    L.CODE=[('io',0x40158886,0x4015897c),('close_and_owner',0x401589e8,0x40158b02),
            ('constructor',0x40158dd6,0x40158e9e)]
    L.DATA=[('file_type',0x402257bc,0x402257c4),('file_vtable',0x402257dc,0x402257ec)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[('parent_path',0x44e6b8d8,0x44e6b9d8)];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    L.EXTRA_BINDINGS={**W.BINDINGS,0x44f37238:0x44647a68,finalize:finalize}
    L.EXTRA_SPANS=[]
    for key in ('sample_manager','sample_loader'):
        L.EXTRA_SPANS+=doc[key]['spans']
        for edit in doc[key]['edits']:
            L.EXTRA_BINDINGS.setdefault(int(edit['target'],16),int(edit['binding'],16))
    # Match the whole standard out_of_range throw helper, including its RTTI
    # name; length_error has the same template body with different operands.
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    old=0x401e46fc;end,rows=B.M.function(donor,old);blob=donor[old-B.BASE:end-B.BASE]
    refs=list(B.M.operands(rows));mask=bytearray(b'\1'*len(blob))
    for at,_,_,_ in refs:mask[at-old:at-old+4]=bytes(4)
    pattern=b''.join(re.escape(bytes([v])) if keep else b'.' for v,keep in zip(blob,mask))
    ti_site=next(at-old for at,target,_,_ in refs if target==0x4022610c)
    def type_name(raw,ti):
        ptr=struct.unpack_from('>I',raw,ti+4-B.BASE)[0]
        return raw[ptr-B.BASE:ptr-B.BASE+80].split(b'\0')[0]
    candidates=[]
    for match in re.finditer(pattern,native,re.S):
        pos=match.start()
        if pos%2:continue
        ti=struct.unpack_from('>I',native,pos+ti_site)[0]
        if type_name(native,ti)!=type_name(donor,0x4022610c):continue
        if all(target not in L.EXTRA_BINDINGS or struct.unpack_from('>I',native,pos+at-old)[0]==L.EXTRA_BINDINGS[target] for at,target,_,_ in refs):candidates.append(B.BASE+pos)
    assert len(candidates)==1,candidates
    L.EXTRA_BINDINGS[old]=candidates[0]
    L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    source=f'''.text
 movea.l 4(%sp),%a0
 tst.l %a0
 beq.s missing
 move.l (%a0),4(%sp)
 jmp {finalize:#x}
missing:
 moveq #-1,%d0
 rts
 .balign 4
'''
    with tempfile.TemporaryDirectory(prefix='file-close-') as temp:
        L.EXTRA_CODE=[('finalize_handle',0x4015b0ce,B.R.assemble(source,0x4015b0ce,Path(temp),'finalize-handle'))]
    L.METHODS={'constructor':0x40158dd6,'read':0x401588fe,'write':0x4015893c,'seek':0x401588ba,
        'close':0x401589e8,'destroy':0x40158a32,'delete':0x40158a5c,'error':0x40158a76,
        'written':0x40158a84,'object_id':0x40158aae,'finalize_handle':0x4015b0ce}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    doc['sample_file'].update(automatic_hash_on_write_close=True,object_bytes=44,
        transfer_dispatch_connected=False,
        limits=['Original constructor replaces an existing target file and creates parent directories.',
                'File class is linked; native host-transfer factory/dispatch still needs integration.'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);build(parser.parse_args().out)
