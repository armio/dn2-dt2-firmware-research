#!/usr/bin/env python3
"""Restore the donor's L1 memory contract for DMA-visible state.

Keep T1D6's valid L2 code layout, but put the PCM state and RPC transport
back in real L1 SRAM. Native cache setup remains byte-identical to stock.
"""
from pathlib import Path
import argparse,json,struct
import build_dt2_dsp_startup_fix as B
C=B.C
BASE=C.ROOT/'output/dn2-research/dt2-dsp-startup-fix-20261010/section_7.bin'
SHA='d5c17b3226ff98d0e47409eb3b7eaaa65057deaecb731c7e58f2e4d9cc26b431'
MOVES=(dict(name='pcm-state',index=132,old=0x200a4000,new=0x2e0000,bytes=0x6100),
       dict(name='rpc-transport',index=170,old=0x200c9000,new=0x2e7000,bytes=0x2070))


def mapped(value):
    for r in MOVES:
        if r['old']<=value<r['old']+r['bytes']:
            return r['new']+value-r['old']
    return value


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    doc=json.loads((BASE.parent/'build-receipt.json').read_text())
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    import sharcinv
    memory=B.decode_view(k,raw);oldmemory=B.decode_view(k,B.BASE.read_bytes())
    blocks=C.B.walk(raw).blocks;by_index={r['index']:r for r in MOVES}
    image=bytearray(raw);edits=[];pointers=[];pcs=[]
    # Original symbol boundaries avoid decoding overwritten instruction tails.
    for r in doc['dsp_startup_fix']['placements']:
        if r['kind']=='code':
            pcs.extend(r['new']+pc-r['old'] for pc in B.boundaries(k,oldmemory,r))
    pcs.extend(B.EXTERNAL_SITES)
    for pc in pcs:
        ins=k.st.decode_at(memory,None,pc);f=sharcinv.merge_fields(ins.fields)
        if ins.type_name in ('17a','16a','19a'):field,value='data32',f['data']
        elif ins.type_name in ('14a','14d'):field,value='addr32',f['addr']
        else:continue
        value2=mapped(value)
        if value2==value:continue
        assert ins.length_bytes==6
        fixed=C.S.retarget(ins.raw,field,pc,value2)
        physical=C.S.code_address(pc,window='l2') if pc>=0xb80000 else C.S.code_address(pc)
        C.B.write_span(image,physical,C.S.to_bytes(fixed))
        edits.append(dict(pc=hex(pc),field=field,before=hex(value),after=hex(value2),
            before_instruction=hex(ins.raw),after_instruction=hex(fixed)))
    # Scan only classified state and pointer objects, never raw audio/coefficients.
    for r in doc['dsp_startup_fix']['placements']:
        if r['kind']!='data':continue
        b=blocks[r['index']]
        for off in range(0,b.count,4):
            assert b.has_payload
            value=struct.unpack_from('<I',image,b.payload_at+off)[0];value2=mapped(value)
            if value2==value:continue
            struct.pack_into('<I',image,b.payload_at+off,value2)
            dest=by_index.get(r['index']);a=(0x28000000+dest['new'] if dest else b.target)+off
            pointers.append(dict(at=hex(a),before=hex(value),after=hex(value2)))
    pieces=[]
    for i,b in enumerate(blocks):
        if i not in by_index:
            pieces.append(bytes(image[b.offset:b.end]));continue
        r=by_index[i];assert b.target==r['old'] and b.count==r['bytes'] and b.has_payload
        dest=0x28000000+r['new']
        assert not B.physical_problem(dest,b.count)
        assert 0x282e0000<=dest<dest+b.count<=0x282ec000
        assert not any(lo<dest+b.count and dest<lo+len(body) for lo,body in C.B.load_regions(raw))
        pieces.append(C.B.block(dest,bytes(image[b.payload_at:b.end])))
    result=b''.join(pieces);assert len(result)==len(raw) and C.B.walk(result).complete
    doc.update(baseline_sha256=SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['dsp_dma_cache_fix']=dict(applied=False,superseded_by='dsp_dma_l1_fix',
        previous_section7_sha256='ec4071aa409852c2272769f6eb63e599c2df71edbb4f2ccdd29ce972bb294500',
        reason='DMA state now resides in native non-cacheable L1; restore stock L2 cache policy.')
    doc['dsp_dma_l1_fix']=dict(reason='Restore original L1 DMA buffer/descriptor placement while keeping added code in valid L2.',
        moves=MOVES,rewritten_instructions=edits,table_pointers=pointers,
        native_cache_policy_unchanged=True,code_addresses_unchanged=True,ddr_pool_unchanged='0x8422b9c8',
        physical_reservation=['0x282e0000','0x282e9070'],
        loaded_native_and_baseline_end='0x282df24a',native_heap_end='0x282dd0b0',dm_cache_start='0x282ec000',
        limitations=['The exact physical T1D7 stall is not observed; this restores the native DT2 transport memory contract.',
            'Native heap, loaded blocks and cache reservations exclude this L1 range; arbitrary computed writers are not universally proven absent.',
            'Hardware boot and transfers remain unverified.'])
    out.mkdir(parents=True,exist_ok=False)
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),bytes=len(result),moves=MOVES,
        rewritten_instructions=len(edits),table_pointers=pointers),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
