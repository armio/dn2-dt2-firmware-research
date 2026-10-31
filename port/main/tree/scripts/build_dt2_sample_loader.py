#!/usr/bin/env python3
"""Link original DT2 sample loading and record ownership for DN2 integration."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-allocator-v2-20261009'
SHA='3d1479c09824a4a2ca078d63badfbf557da2863916dd0b191db8f0d1e17b4dec'
ENTRIES={'load':0x40154540,'unload':0x401540c6,'clear_slot':0x40153bea,
         'reindex':0x4015366e}


def build(out):
    donor=B.M.S.DONOR.read_bytes();doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_loader';L.LIMIT=0x47a88000
    L.CODE=[(n,a,B.M.function(donor,a)[0]) for n,a in ENTRIES.items()]
    L.DATA=[('scope_exit_vtable',0x401f43a8,0x401f43b8),
            ('scope_exit_type',0x401f40f0,0x401f40f8),
            ('load_lambda_type',0x402256bc,0x402256c4)]
    L.DIRECTORY_AUX=False;L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[]
    L.EXTRA_DATA={}
    # Reserve these tables explicitly in the existing pre-BSS copy. This
    # avoids self-modifying heap-address operands after caches are enabled.
    L.EXTRA_STATE=[('slot_metadata',0x405b1360,0x405ba768),
                   ('slot_rates',0x405bb768,0x405bc768),
                   ('notification_records',0x405a0f9c,0x405a4fa0),
                   ('notification_queue',0x402b6628,0x402b662c),
                   ('path_buffer',0x405a4fa0,0x405a50a0)]
    L.EXTRA_SPANS=[];bindings={}
    for key in ('pcm_pages','sample_allocator'):
        L.EXTRA_SPANS.extend(doc[key]['spans'])
        for edit in doc[key]['edits']:
            bindings[int(edit['target'],16)]=int(edit['binding'],16)
    bindings.update({0x401360ac:0x40134490,0x401360f4:0x401344d8,
                     0x402258b8:0x4020eeb4,
                     0x4011e8f0:0x40120264,0x4011e8fc:0x40120270,
                     0x4011e8f6:0x4012026a,0x4011e902:0x40120276})
    # This noreturn function ends at the next entry, not an RTS. Match its
    # complete body AND thrown RTTI; several other throw helpers share it.
    native=B.M.RECIPIENT.read_bytes();throw=bytearray(donor[0x401e4446-B.BASE:0x401e4470-B.BASE])
    queue_end,_=B.M.function(donor,0x40001896)
    assert donor[0x40001896-B.BASE:queue_end-B.BASE]==native[0x40001896-B.BASE:queue_end-B.BASE]
    bindings[0x40001896]=0x40001896
    throw_map={0x401e7e5e:0x401cea98,0x40225a94:0x4020f090,
               0x401e7d82:0x401ce9bc,0x40225cd8:0x4020f2d4,0x401e8d20:0x401cf95a}
    for operand,target,_,_ in B.M.operands(B.M.S.disasm(donor,B.BASE,0x401e4446,0x401e4470)):
        struct.pack_into('>I',throw,operand-0x401e4446,throw_map[target])
    assert throw==native[0x401cb080-B.BASE:0x401cb0aa-B.BASE]
    for image,ti in ((donor,0x40225cd8),(native,0x4020f2d4)):
        name=struct.unpack_from('>I',image,ti+4-B.BASE)[0]
        assert image[name-B.BASE:name-B.BASE+13]==b'St9bad_alloc\0'
    bindings[0x401e4446]=0x401cb080
    length_throw=bytearray(donor[0x401e466e-B.BASE:0x401e46fc-B.BASE])
    length_map={0x401e7e5e:0x401cea98,0x401e7a64:0x401ce69e,
        0x401e9628:0x401d0262,0x401e5f98:0x401ccbd2,0x401e93d8:0x401d0012,
        0x40226100:0x4020f6fc,0x401e8d20:0x401cf95a,0x401e7efe:0x401ceb38,
        0x40186872:0x4017b966}
    for operand,target,_,_ in B.M.operands(B.M.S.disasm(donor,B.BASE,0x401e466e,0x401e46fc)):
        struct.pack_into('>I',length_throw,operand-0x401e466e,length_map[target])
    assert length_throw==native[0x401cb2a8-B.BASE:0x401cb336-B.BASE]
    for image,ti in ((donor,0x40226100),(native,0x4020f6fc)):
        name=struct.unpack_from('>I',image,ti+4-B.BASE)[0]
        assert image[name-B.BASE:name-B.BASE+17]==b'St12length_error\0'
    bindings[0x401e466e]=0x401cb2a8
    L.EXTRA_BINDINGS=bindings;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.RESERVE_VENEERS=True;L.METHODS=ENTRIES
    L.build(out)
    result=json.loads((out/'build-receipt.json').read_text())
    cfg=result['sample_loader'];copy=result['runtime_copy'];base=int(copy['destination'],16)
    def address(old):
        for s in cfg['spans']:
            lo,hi=int(s['donor'],16),int(s['end'],16)
            if lo<=old<hi:return int(s['runtime'],16)+old-lo
        for e in cfg['edits']:
            if int(e['target'],16)==old:return int(e['binding'],16)
        raise AssertionError(hex(old))
    payload=bytearray((out/'runtime.bin').read_bytes())
    # Exact table values from the original initialization loop40153C86..CB6.
    # No1024 empty-descriptor broadcasts and no post-startup code patching.
    for slot in range(1024):
        for old,value in ((0x405bc768+slot*4,address(0x4023f364)),
                          (0x405bb768+slot*4,0),(0x405ba768+slot*4,0),
                          (0x405b5368+slot*4,0xffffffff),
                          (0x405b1368+slot*16,0xffffffff)):
            # Existing names/sizes arrays are inherited as base bindings.
            if 0x405bc768<=old<0x405bd768:at=address(0x405bc768)+old-0x405bc768
            elif 0x405ba768<=old<0x405bb768:at=address(0x405ba768)+old-0x405ba768
            else:at=address(old)
            struct.pack_into('>I',payload,at-base,value)
    image=bytearray((out/'main-os.bin').read_bytes());src=int(copy['source'],16)-B.BASE
    image[src:src+len(payload)]=payload
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    result.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload))
    result.update(flash_ready=False)
    result['sample_loader'].update(private_state_bytes=0xe510,
        startup_tables_initialized=True,
        connected_to_picker=False,
        limits=['Explicit private cap extended64KiB below the existing bank-0 stack top; hardware high-water proof pending',
                'Notification queue and project wrapper integration remain pending'])
    (out/'build-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(final_main_sha256=result['main_sha256'],private_state_bytes=0xe510),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
