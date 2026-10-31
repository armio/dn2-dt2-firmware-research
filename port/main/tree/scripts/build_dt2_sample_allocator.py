#!/usr/bin/env python3
"""Port DT2 allocation queries with a private allocation-record vector."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-pcm-pages-20261009'
SHA='81a1a9a24b992362bda0e2262a6f62dc3ad2b94c765d4438619cc5d76aabe336'
ENTRIES={'find_identity':0x401535c2,'free_bytes':0x401537e0,
         'total_bytes':0x4015381e,'tail_fit':0x401543a6,'fit':0x4015444e}


def build(out):
    donor=B.M.S.DONOR.read_bytes()
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_allocator';L.LIMIT=0x47a78000
    L.CODE=[(name,entry,B.M.function(donor,entry)[0]) for name,entry in ENTRIES.items()]
    L.DATA=[];L.DIRECTORY_AUX=False;L.EXTRA_DATA={};L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[]
    # Vector storage belongs to the sample allocator; its backing records will
    # be allocated by the original load/erase routines, not a fixed slot limit.
    L.EXTRA_STATE=[('allocation_vector',0x405a0f64,0x405a0f70)]
    L.EXTRA_BINDINGS={0x401360ac:0x40134490,0x401360f4:0x401344d8,
                      0x4011e8f0:0x40120264,0x4011e8fc:0x40120270}
    # STL tree-copy shells may be byte-identical while their node-copy callee
    # has a different payload type. Do not infer such a callee from its caller.
    L.INFER_NATIVE_LIBRARY_OPERANDS=False;L.RESERVE_VENEERS=True;L.METHODS=ENTRIES
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    image=bytearray((out/'main-os.bin').read_bytes());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray((out/'runtime.bin').read_bytes());cfg=doc['sample_allocator']
    sites=[]
    for name in ('free_bytes','total_bytes','fit'):
        target=ENTRIES[name];dest=int(cfg['methods'][name],16)
        for edit in doc['sample_manager']['edits']:
            if int(edit['target'],16)!=target:continue
            assert edit['kind']=='absolute operand'
            offset=int(edit['runtime'],16)-base
            assert payload[offset:offset+4]==B.BE(int(edit['binding'],16))
            struct.pack_into('>I',payload,offset,dest);edit['binding']=hex(dest)
            sites.append(dict(method=name,site=edit['runtime']))
        del doc['sample_manager']['unresolved_services'][hex(target)]
    cfg.update(manager_call_sites=sites,record_stride=52,
        donor_pool_bytes=0x19000000,connected_to_picker=True,
        limits=['Original DT2 capacity is retained as a donor constant; DN2 memory ownership remains unproven',
                'Load/unload and preview are not yet connected to this private vector',
                'Query port does not allocate or write PCM memory'])
    image[src-B.BASE:src-B.BASE+len(payload)]=payload
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],remaining_services=doc['sample_manager']['unresolved_services']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
