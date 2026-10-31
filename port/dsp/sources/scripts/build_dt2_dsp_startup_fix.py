#!/usr/bin/env python3
"""Move DT2 additions out of absent/cache-reserved SHARC L1 memory.

T1D5 placed the receiver at byte 0x2f4000 (a physical hole), and later
recording code beyond block 2's end at 0x320000. A flat-memory component
runner did not model this restriction. Keep the previously working ONESHOT
image and external DDR tables; relocate later L1 additions into a bounded
L2 reservation below the native DMA buffers.
"""
from pathlib import Path
import argparse, collections, json, re, struct
import build_dt2_sampler_dsp as C

BASE = C.ROOT/'output/dn2-research/dt2-sample-cursor-dsp-20261009/section_7.bin'
SHA = '538d4893dde427b37cfb8cc920543847ae4b69e766cb3e42c0b399b27eadbf18'
START, LIMIT, ORIGINAL_START = 0x20090000, 0x200f0000, 0x282e0000
FIRST, FINAL = 117, 205
# Explicit code/data classification from the producer scripts. Never decode
# coefficient tables as instructions or search-and-replace arbitrary words.
CODE_IDS = frozenset((117,118,119,120,121,122,123,125,128,129,130,131,133,
    134,135,137,138,139,141,145,146,147,153,154,155,157,159,160,163,164,165,
    167,169,172,173,174,175,177,178,180,181,182,186,187,188,189,190,195,
    196,197,201,202,203))
# Changed native/earlier ONESHOT instructions in the append-only build chain.
EXTERNAL_SITES = (0x1c2958,0x185a23,0x1856af,0x185b7f,0x185d03,0x18617b,
    0x185a38,0x185ac3,0x16f81e,0x185800,0x185737,0x16f54f,
    0x1c9b33,0x1ca81b,0x1ca822,0x1ca72d,0x1c309a,0x1c14ab,0x1c944c)
L1 = ((0x28240000,0x28270000),(0x282c0000,0x282f0000),
      (0x28300000,0x28320000),(0x28380000,0x283a0000))
CACHE = ((0x282ec000,0x282f0000),(0x2831c000,0x28320000),
         (0x2839c000,0x283a0000))
OBJECTS={123:('dt2-sampler-frame-v4-20261009','frame'),
    125:('dt2-werp-live-v3-20261009/dsp','dispatch'),
    134:('dt2-voice-samples-20261009','voice-samples'),
    137:('dt2-stereo-mixer-v2-20261009','stereo-mixer'),
    141:('dt2-stereo-voices-v2-20261009','stereo-voices'),
    154:('dn2-right-process-20261009','effects-entry'),
    155:('dn2-right-process-20261009','effects-return'),
    157:('dn2-right-hooks-20261009','right-hooks'),
    159:('dt2-stereo-pan-20261009','stereo-pan'),
    163:('dt2-stereo-balance-20261009','stereo-balance'),
    165:('dt2-output-hook-20261009','output-hook'),
    203:('dt2-sample-cursor-dsp-20261009','cursor-publish')}


def physical_problem(a, n):
    if not 0x28000000 <= a < 0x28400000:
        return None
    if not any(lo <= a and a+n <= hi for lo,hi in L1):
        return 'outside physical L1'
    if any(a < hi and lo < a+n for lo,hi in CACHE):
        return 'cache reservation'
    return None


def plan(raw):
    cursor=START; records=[]
    for i,b in enumerate(C.B.walk(raw).blocks):
        if not FIRST <= i < FINAL or not 0x28200000 <= b.target < 0x28400000:
            continue
        # Preserve cross-object address arithmetic, notably original mixer
        # I15=pointer_table+0x240 with native accesses at I15-0x240.
        cursor=START+b.target-ORIGINAL_START
        kind='code' if i in CODE_IDS else 'data'
        old=(b.target-0x28000000)//2 if kind=='code' else b.target-0x28000000
        new=0xb80000+(cursor-0x20000000)//2 if kind=='code' else cursor
        records.append(dict(index=i,kind=kind,old=old,new=new,
            old_physical=b.target,new_physical=cursor,bytes=b.count))
        cursor+=b.count
    cursor=max(r['new_physical']+r['bytes'] for r in records)
    assert cursor <= LIMIT and {r['index'] for r in records if r['kind']=='code'}==CODE_IDS
    assert not any(a < cursor and START < a+len(b) for a,b in C.B.load_regions(raw))
    return records


def mapped(value, records):
    for r in records:
        size=r['bytes']//2 if r['kind']=='code' else r['bytes']
        if r['old'] <= value < r['old']+size:
            return r['new']+value-r['old']
        # DMA bus addresses, if present, use the full byte alias.
        if r['old_physical'] <= value < r['old_physical']+r['bytes']:
            return r['new_physical']+value-r['old_physical']
    return value


def decode_view(k, raw):
    # decode_at requests six bytes even for the final two-byte instruction.
    # Real placement reserves alignment padding; provide that lookahead only
    # for decoding, without changing firmware contents.
    extras=[]
    for i,b in enumerate(C.B.walk(raw).blocks):
        if i in CODE_IDS:
            extras.append(C.B.block(b.target+b.count, bytes(4)))
    return k.ldr.LoadedMemory.from_stream(C.B.insert_before_final(raw,b''.join(extras)))


def rewrite(ins, pc, dest, records):
    import sharcinv
    fields=sharcinv.merge_fields(ins.fields)
    form=ins.type_name; field=value=None; raw=ins.raw
    if form in ('25a_direct','8a_abs'):
        field,value='addr24',fields['addr']
    elif form in ('8a_rel','25a_pcrel'):
        field,value='rel24',pc+C.S.get_field(raw,'rel24')
    elif form in ('17a','16a','19a'):
        field,value='data32',fields['data']
    elif form in ('14a','14d'):
        field,value='addr32',fields['addr']
    if field is None:
        return raw,None
    target=mapped(value,records)
    if target==value and (field!='rel24' or pc==dest):
        return raw,None
    mode=field
    if field=='rel24' and not -(1<<23) <= target-dest < (1<<23):
        # 8a absolute and PC-relative differ only in the addressing-mode bit.
        # Preserve the condition, call bit, delayed bit and clear-interrupt bit.
        assert form=='8a_rel' and raw>>40==7,(hex(pc),form,hex(raw))
        raw &= ~(1<<40)
        field='addr24';mode='relative-to-absolute'
    fixed=C.S.retarget(raw,field,dest,target)
    return fixed,dict(pc=hex(pc),new_pc=hex(dest),kind=mode,
        before=hex(value),after=hex(target),before_instruction=hex(ins.raw),
        after_instruction=hex(fixed))


def boundaries(k, memory, r):
    """Instruction starts from compiler symbols or original decoded listing.

    In particular the right-process hook overwrites six bytes across two
    original instructions; the remainder is unreachable and is not a new
    instruction to decode. Selas's short ADD also has an ambiguous decode.
    """
    if r['index'] in OBJECTS:
        from dnfw.image import sharc_object as O
        folder,name=OBJECTS[r['index']]
        syms=O.symbols((C.ROOT/'output/dn2-research'/folder/(name+'.doj')).read_bytes())
        result=sorted(r['old']+v for n,v in syms.items() if re.fullmatch(r'x_i\d+',n))
        if r['index']==203:
            # The cursor producer appends two displaced native loads and jump.
            result += [r['old']+(r['bytes']-14)//2,r['old']+(r['bytes']-10)//2,
                       r['old']+(r['bytes']-6)//2]
        assert result[0]==r['old'] and result[-1]<r['old']+r['bytes']//2
        return result
    if r['index']==153:
        folder=C.ROOT/'output/dn2-research/dn2-right-process-20261009'
        result=[int(re.match(r'[0-9a-f]+ -> ([0-9a-f]+)',l)[1],16)
                for l in (folder/'native-process.asm').read_text().splitlines()]
        patches=json.loads((folder/'build-receipt.json').read_text())['patches']
        for p in patches:
            at=int(p['target'],16)
            result=[pc for pc in result if not at<pc<at+3]
        return result
    result=[];pc=r['old'];end=pc+r['bytes']//2
    while pc<end:
        ins=k.st.decode_at(memory,None,pc)
        assert ins.kind!='unknown' and ins.length_bytes and pc+ins.length_bytes//2<=end,hex(pc)
        result.append(pc);pc+=ins.length_bytes//2
    return result


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    out.mkdir(parents=True,exist_ok=False)
    records=plan(raw);by_index={r['index']:r for r in records}
    k=C.M.Digikit(C.SRC/'toolchains/digikit');memory=decode_view(k,raw)
    original=k.ldr.LoadedMemory.from_stream(raw)
    patched=bytearray(raw);relocations=[]
    for pc in EXTERNAL_SITES:
        ins=k.st.decode_at(original,None,pc)
        fixed,event=rewrite(ins,pc,pc,records)
        if event:
            C.B.write_span(patched,C.S.code_address(pc),C.S.to_bytes(fixed))
            relocations.append(event)
    blocks=C.B.walk(raw).blocks;pieces=[];pointers=[];instruction_count=0
    for i,b in enumerate(blocks):
        if i not in by_index:
            if b.target==0x805d9400:
                assert b.count==19*4
                body=bytearray(patched[b.payload_at:b.end])
                for off in range(0,len(body),4):
                    old=struct.unpack_from('<I',body,off)[0];new=mapped(old,records)
                    assert 0x175000<=old<0x175d6c and new!=old
                    struct.pack_into('<I',body,off,new)
                    pointers.append(dict(at=hex(b.target+off),before=hex(old),after=hex(new)))
                pieces.append(C.B.block(b.target,bytes(body)))
            else:
                pieces.append(bytes(patched[b.offset:b.end]))
            continue
        r=by_index[i]
        body=bytearray(raw[b.payload_at:b.end]) if b.has_payload else bytearray(b.count)
        if r['kind']=='code':
            for pc in boundaries(k,memory,r):
                ins=k.st.decode_at(memory,None,pc)
                assert ins.kind!='unknown' and ins.length_bytes,hex(pc)
                dest=r['new']+pc-r['old']
                fixed,event=rewrite(ins,pc,dest,records)
                if event:
                    assert ins.length_bytes==6
                    off=2*(pc-r['old']);body[off:off+6]=C.S.to_bytes(fixed)
                    relocations.append(event)
                instruction_count+=1
        else:
            # Only explicitly classified L1 state/dispatch tables. External
            # DDR coefficient and audio data are never scanned as pointers.
            assert len(body)%4==0
            for off in range(0,len(body),4):
                old=struct.unpack_from('<I',body,off)[0];new=mapped(old,records)
                if old!=new:
                    struct.pack_into('<I',body,off,new)
                    pointers.append(dict(at=hex(r['new_physical']+off),before=hex(old),after=hex(new)))
        pieces.append(C.B.block(r['new_physical'],bytes(body)))
    image=b''.join(pieces)
    # Correct the second application's FIRST block byte-span after insertion.
    # It records the offset to the terminating block (native convention).
    walk=C.B.walk(image);first=walk.blocks[7];last=walk.blocks[-1]
    assert first.flags==0x50 and last.flags==0x80
    newfirst=C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)
    image=image[:first.offset]+newfirst+image[first.end:]
    walk=C.B.walk(image);assert walk.complete
    problems=[dict(target=hex(b.target),bytes=b.count,reason=physical_problem(b.target,b.count))
              for b in walk.blocks if b.count and physical_problem(b.target,b.count)]
    assert not problems,problems
    bad_before=[dict(index=i,target=hex(b.target),bytes=b.count,reason=physical_problem(b.target,b.count))
        for i,b in enumerate(blocks) if b.count and physical_problem(b.target,b.count)]
    doc=json.loads((BASE.parent/'build-receipt.json').read_text())
    doc.update(baseline_sha256=SHA,section7_sha256=C.SHA(image),flash_ready=False)
    doc['dsp_startup_fix']=dict(reason='Appended blocks targeted physical holes and cache-reserved L1 memory.',
        reservation=[hex(START),hex(max(r['new_physical']+r['bytes'] for r in records))],
        reservation_limit=hex(LIMIT),native_l2_last_byte='0x2008823c',
        native_dma_reserved=['0x200fa000','0x200fe000'],placements=records,
        preserves_relative_placement=True,
        invalid_original_blocks=bad_before,rewritten_instructions=relocations,
        table_pointers=pointers,decoded_instructions=instruction_count,
        first_header_span=dict(before=hex(first.argument),after=hex(last.offset-first.offset)),
        references=['digikit/docs/findings/06-sharc-engine-and-startup.md:3170',
            str(C.SRC/'docs/for-digikit-sharc-runner-memory-map.md'),
            str(C.SRC/'docs/waverider-dsp-compare.md')],
        limitations=['Native DMA/IRQ and scheduler operation still require hardware confirmation.',
                    'Static placement excludes all loaded native regions and the known runtime DMA window.'])
    (out/'section_7.bin').write_bytes(image)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(image),bytes=len(image),
        moved_blocks=len(records),invalid_original_blocks=len(bad_before),
        rewritten_instructions=len(relocations),table_pointers=len(pointers),
        reservation=doc['dsp_startup_fix']['reservation']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
