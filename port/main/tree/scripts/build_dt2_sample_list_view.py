#!/usr/bin/env python3
"""Link complete native SampleListView construction, events and lifetime.

Unported project/sample-picker imports remain explicit diagnostic stops.
This component is not exposed to the running UI or packaged for flashing.
"""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_sample_list_model as B


def build(out):
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    # The native project-root singleton has identical instructions and fields;
    # its allocated root is 0x44 bytes larger on DN2. The native factory must
    # construct the DN2 root, never the donor one.
    lo,hi,dest=0x401988a2,0x40198948,0x4018a97a
    d=bytearray(donor[lo-B.BASE:hi-B.BASE]);n=bytearray(native[dest-B.BASE:dest-B.BASE+len(d)])
    assert struct.unpack_from('>I',d,0x14)[0]==0x6e3c8
    assert struct.unpack_from('>I',n,0x14)[0]==0x6e40c
    d[0x14:0x18]=n[0x14:0x18]=bytes(4)
    for at,_,_,_ in B.M.operands(B.M.S.disasm(donor,B.BASE,lo,hi)):
        off=at-lo;d[off:off+4]=n[off:off+4]=bytes(4)
    assert d==n
    # Verify the standard shared-count base vtable's RTTI owner.
    assert donor[0x401ec59c-B.BASE:0x401ec5a4-B.BASE]==struct.pack('>II',0,0x401ec32c)
    assert native[0x401d3de4-B.BASE:0x401d3dec-B.BASE]==struct.pack('>II',0,0x401d3b54)
    B.EXTRA_BINDINGS={lo:dest,0x401ec5a4:0x401d3dec}
    B.RTTI_MATCHES += [(0x40216784,0x40200158),(0x401eced4,0x401d3b60)]
    # Exclude the static-singleton shutdown function at 1e110..1e17a; it is
    # not a view method. This avoids installing foreign global shutdown state.
    B.CODE=[('view_front',0x4001dd9c,0x4001e110),
            ('view_body',0x4001e17a,0x4001efac),
            ('view_lifetime',0x4019b728,0x4019b83e),
            ('view_factory',0x40199eb2,0x40199f22),
            ('shared_destructors',0x40199a52,0x40199a6e),
            ('shared_destroy',0x40199a8e,0x40199a9e),
            ('shared_dispose_tag',0x40199adc,0x40199b2a),*B.CODE[3:]]
    B.DATA=[*B.DATA[:2],('view_rtti',0x401ee45c,0x401ee4a4),
            ('view_vtables',0x401ee4b0,0x401ee5e0),
            ('shared_rtti',0x401ed858,0x401ed864),('shared_vtable',0x401ed9d8,0x401ed9f4)]
    B.CODE_HOLES=[(0x4001ebf8,0x4001ec16)]
    B.IMPORTS.update({0x4004297c:'Resolve active sampler parameter object',
                      0x4019b89a:'Native +Drive SamplePicker factory',
                      0x4003b570:'Apply donor sample ID through DN2 parameter map'})
    B.build(out)
    f=out/'build-receipt.json';receipt=json.loads(f.read_text());methods=receipt['pool_model']['methods']
    def mapped(at):
        for name,lo,hi in B.CODE+B.DATA:
            if lo<=at<hi:return int(methods[name],16)+at-lo
        raise ValueError(hex(at))
    entries={'constructor':0x4001e4ae,'factory':0x40199eb2,'destroy':0x4019b728,
             'delete':0x4019b7f2,'draw':0x4001e78a,'event':0x4001ebc8,
             'close':0x4001e1fe,'set_slot':0x4001e0ac,'get_slot':0x4001e17a,
             'rebuild':0x4001e31a,'set_mode':0x4001e0f8,'set_preview_mode':0x4001e104}
    receipt['sample_list_view']=dict(methods={k:hex(mapped(v)) for k,v in entries.items()},
        connected_to_ui=False,project_root_binding=dict(donor=hex(lo),dn2=hex(dest),
            donor_object_bytes=0x6e3c8,dn2_object_bytes=0x6e40c),
        event_jump_table='Original 15 signed relative entries retained as data',
        unresolved=receipt['pool_model']['unresolved'],
        remaining=['Resolve named imports','Pool loading/restoration','Audition/commit callbacks','SYN page routing'])
    f.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt['sample_list_view'],indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
