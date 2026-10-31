#!/usr/bin/env python3
"""Link native DT2 sampler setters, setup branches and alternate renderer.

Offline component: no dispatcher/menu hook or SysEx. The donor fatal-assert
boundary is an explicit diagnostic stop pending DN2 fault-handler integration.
"""
from pathlib import Path
import argparse, collections, hashlib, json, sys
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'firmware/ghidra/oneshot-proof/v7-source'
sys.path[:0]=[str(SRC/'src'),str(SRC/'scripts')]
import sharc_waverider_render as M
from dnfw.image import bootstream as B
from dnfw.transplant import sharc as S
SHA=lambda b:hashlib.sha256(b).hexdigest()
BASELINE=ROOT/'output/dn2-research/oneshot-native-bounds-dsp-v2-20261008/section_7.bin'
BASELINE_SHA='6c9658f6c7020a0b303e7f85b4b8f3deb1fd713c27fce94c9eebf4c7dcd3fe9e'
DONOR=ROOT/'firmware/dt2-1.16/section_7_blob.bin'
DONOR_SHA='0f514a12a2255f5c081e292c47f1f29462003177658da4bbae0a22fd737fffa2'
# Endpoints include all return/delay-slot instructions. SLICE's setup ends
# at 69C6, not 69C4 as the old inventory stated.
SPANS=(('setters',0x1c4a31,0x1c4e70,0x170000),
       ('alternate-render',0x1c5576,0x1c59c3,0x170500),
       ('setup',0x1c6715,0x1c69c6,0x170a00),
       ('scalb',0x1c0c36,0x1c0c3f,0x170d00))
EXIT,FAULT=0x170d20,0x170d30
EXTERNAL={0x1c06ba:0x185480,0x1c4914:0x16f580,
          0xb88f06:0x187ec0,0xb88f70:0x16f700,
          0x1c0d68:0x1c0c76,0x1c65fe:EXIT,0xb8907a:FAULT}
ENTRIES={'REPITCH':0x1c4a31,'ONESHOT_WERP_GRID':0x1c4afe,
         'SLICE':0x1c4bf9,'STRETCH':0x1c4d88,
         'alternate-render':0x1c5576,'WERP-setup':0x1c6715,
         'STRETCH-setup':0x1c6782,'REPITCH-setup':0x1c686e,
         'GRID-setup':0x1c692f,'SLICE-setup':0x1c6992}


def mapped(address):
    for _,lo,hi,new in SPANS:
        if lo<=address<hi:return new+address-lo
    if address in EXTERNAL:return EXTERNAL[address]
    raise ValueError(f'Unbound native address {address:#x}')


def build(folder):
    folder.mkdir(parents=True,exist_ok=False)
    donor,base=DONOR.read_bytes(),BASELINE.read_bytes()
    assert SHA(donor)==DONOR_SHA and SHA(base)==BASELINE_SHA
    dk=M.Digikit(SRC/'toolchains/digikit')
    import sharcfn, sharcinv
    memory=dk.ldr.LoadedMemory.from_stream(donor)
    # Existing imports are pinned by the full baseline hash. These conversion
    # and divide bodies are also byte-identical to their donor originals.
    recipient=dk.ldr.LoadedMemory.from_stream(base)
    for old,new,size in [(0xb88f70,0x16f700,244),(0xb88f06,0x187ec0,212),
                         (0x1c06ba,0x185480,222)]:
        assert memory.read_sw(old,size)==recipient.read_sw(new,size),(hex(old),hex(new))
    blocks=[];reports=[];relocations=[]
    for name,lo,hi,new in SPANS:
        original=memory.read_sw(lo,(hi-lo)*2);code=bytearray(original)
        pc=lo;listing=[];count=0
        while pc<hi:
            ins=dk.st.decode_at(memory,None,pc)
            assert ins.length_bytes and pc+ins.length_bytes//2<=hi,(name,hex(pc))
            assert ins.kind!='unknown',(name,hex(pc))
            fields=sharcinv.merge_fields(ins.fields)
            form=ins.type_name;target=field=None
            if form in ('25a_direct','8a_abs'):
                target=fields['addr'];field='addr24'
            elif form in ('8a_rel','25a_pcrel'):
                target=(pc+S.get_field(ins.raw,'rel24'))&0xffffff;field='rel24'
            elif form=='16a' and fields.get('i')==7 and fields.get('m')==7:
                # Compiler-linked return address minus one (not arbitrary data).
                target=fields['data'];field='data32'
            elif form=='17a' and fields.get('data')==0x25d858:
                # This assertion message belongs to the donor OS. The fault
                # boundary never dereferences it; replace with a diagnostic tag.
                target=None
                off=2*(pc-lo)
                code[off:off+6]=S.to_bytes(S.set_field(ins.raw,'data32',0x534c4943))
                relocations.append({'span':name,'pc':hex(pc),'kind':'fault diagnostic tag',
                                    'before':hex(0x25d858),'after':hex(0x534c4943)})
            if target is not None:
                dest=mapped(target);newpc=new+pc-lo
                replacement=S.retarget(ins.raw,field,newpc,dest)
                off=2*(pc-lo);code[off:off+6]=S.to_bytes(replacement)
                if replacement!=ins.raw:
                    relocations.append({'span':name,'pc':hex(pc),'kind':field,
                                        'before':hex(target),'after':hex(dest)})
            text=sharcfn.render_instruction(pc,ins,memory,set(),collections.Counter(),[])[0]
            listing.append(f'{pc:08x} -> {new+pc-lo:08x} {text}')
            pc+=ins.length_bytes//2;count+=1
        assert pc==hi
        (folder/(name+'.bin')).write_bytes(code)
        (folder/(name+'.asm')).write_text('\n'.join(listing)+'\n')
        blocks.append((S.code_address(new),bytes(code)))
        reports.append({'name':name,'donor_start':hex(lo),'donor_end':hex(hi),
                        'recipient_start':hex(new),'bytes':len(code),'instructions':count,
                        'donor_sha256':SHA(original),'relocated_sha256':SHA(code)})
    # Ordinary, non-delayed hardware RETURN and absolute self-loop. The latter
    # deliberately cannot masquerade as a successful assert return.
    blocks.extend([(S.code_address(EXIT),bytes.fromhex('3e0a00000000')),
                   (S.code_address(FAULT),S.to_bytes(0x063e00000000|FAULT))])
    placements=[]
    for at,payload in blocks:
        assert 0x282e0000<=at<at+len(payload)<=0x28300000
        assert not any(a<at+len(payload) and at<a+len(b) for a,b in B.load_regions(base))
        assert not any(a<at+len(payload) and at<a+n for a,n in placements)
        placements.append((at,len(payload)))
    linked=B.insert_before_final(base,b''.join(B.block(at,payload) for at,payload in blocks))
    (folder/'section_7.bin').write_bytes(linked)
    report={'donor_sha256':DONOR_SHA,'baseline_sha256':BASELINE_SHA,
            'section7_sha256':SHA(linked),'spans':reports,'relocations':relocations,
            'entries':{name:hex(mapped(at)) for name,at in ENTRIES.items()},
            'setup_exit':hex(EXIT),'unbound_fault_stop':hex(FAULT),
            'external_bindings':{hex(k):hex(v) for k,v in EXTERNAL.items()},
            'dispatcher_changed':False,'flash_ready':False,
            'remaining':['DN2 Machine selection and per-voice setup adapters',
                         'Transport/tempo and slice metadata inputs',
                         'Alternate renderer state/lifecycle integration',
                         'Bind fatal assertion to DN2 diagnostics before delivery'],
            'scope':'Relocated native DSP code; valid-path execution requires caller ABI and state. No hardware claim.'}
    (folder/'build-receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'bytes_imported':sum(p['bytes'] for p in reports),
                      'relocations':len(relocations),'section7_sha256':SHA(linked),'flash_ready':False}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path)
    build(p.parse_args().output)
