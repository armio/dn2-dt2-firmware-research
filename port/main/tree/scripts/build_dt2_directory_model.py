#!/usr/bin/env python3
"""Relocate DT2 FileSystemDirectory and its actual ownership/navigation code."""
from pathlib import Path
import argparse, json, re, struct
import build_dt2_drive_services as D
B = D.B
INPUT = B.T.ROOT/'output/dn2-research/dt2-drive-services-20261009'
SHA = '67e2db7ae52800f17af3115264f607199f85faf31d9f09453b328aec8f0460fd'
LIMIT = 0x47a68000
COMPONENT = 'directory_model'
CODE = [('directory',0x40159298,0x40159f50),('entry_owner',0x401e2978,0x401e29e8)]
DATA = [('directory_types',0x40225834,0x402258b0)]
DIRECTORY_AUX = True
EXTRA_BINDINGS = {}
EXTRA_DATA = {}
EXTRA_STATE = []
STATE_ALIGNMENT = 4
EXTRA_CODE = []
EXTRA_TYPED_DATA = []
EXTRA_SPANS = []
INFER_NATIVE_LIBRARY_OPERANDS = False
RESERVE_VENEERS = False
METHODS = {'constructor':0x40159ca0,'constructor_at':0x40159cf6,'destroy':0x40159ee0,
           'rebuild':0x40159a2c,'count':0x40159298,'name':0x401592b6,
           'row_id':0x401595ac,'find_row':0x40159628,'navigate':0x40159dd2,
           'enter':0x40159d5a,'parent':0x40159d8e,'current_id':0x40159912}


def build(out):
    raw = (INPUT/'main-os.bin').read_bytes(); assert B.T.SHA(raw) == SHA
    donor = B.M.S.DONOR.read_bytes(); assert B.T.SHA(donor) == B.M.S.SHA
    native = B.M.RECIPIENT.read_bytes()
    doc = json.loads((INPUT/'build-receipt.json').read_text()); copy = doc['runtime_copy']
    base,src = int(copy['destination'],16),int(copy['source'],16)
    payload = bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']])
    out.mkdir(parents=True,exist_ok=False)
    bindings = {}
    for key in ('pool_model','sample_list'):
        for edit in doc[key].get('edits',doc[key].get('patches',[])):
            if not edit.get('relative'):
                bindings[int(edit['before'],16)] = int(edit['after'],16)
    bindings.update(D.mapping(INPUT/'fn_new_map.txt'))
    bindings.update(D.mapping(INPUT/'ram_map.txt'))
    bindings.update({0x400015a0:0x400015a0,0x400016d2:0x400016d2})
    inherited_spans=list(EXTRA_SPANS)
    for section in ('directory_model','browser_popup'):
        if section in doc:
            inherited_spans.extend(doc[section]['spans'])
            for edit in doc[section]['edits']:
                bindings[int(edit['target'],16)]=int(edit['binding'],16)
    bindings.update(EXTRA_BINDINGS)
    spans, queue, edits, evidence = [], [], [], []
    reserved_veneers = {}
    def append(blob):
        payload.extend(bytes(-len(payload)%4)); at=base+len(payload)
        payload.extend(blob); return at
    def add_code(name,lo,hi,rows=None):
        rows=rows or list(B.M.S.disasm(donor,B.BASE,lo,hi))
        at=append(donor[lo-B.BASE:hi-B.BASE]); spans.append((name,lo,hi,at,'code'))
        queue.append((name,lo,hi,at,rows))
        if RESERVE_VENEERS:
            for pc,hx,mn,ops in rows:
                match=re.search(r'\$([0-9a-f]{8})(\(pc\))?',ops)
                if match and (match[2] or mn.split('.')[0] in B.M.BRANCHES):
                    if not lo<=int(match[1],16)<hi:
                        reserved_veneers[(at,pc)]=append(bytes(6))
        return at
    def add_data(name,lo,hi):
        at=append(donor[lo-B.BASE:hi-B.BASE]); spans.append((name,lo,hi,at,'data'));return at
    # Keep the entire contiguous class so local short branches are unchanged.
    for name,lo,hi in CODE:add_code(name,lo,hi)
    for name,lo,hi in DATA:add_data(name,lo,hi)
    for name,lo,blob in EXTRA_TYPED_DATA:
        spans.append((name,lo,lo+len(blob),append(blob),'data'))
    for name,lo,hi in EXTRA_STATE:
        payload.extend(bytes(-(base+len(payload))%STATE_ALIGNMENT))
        spans.append((name,lo,hi,append(bytes(hi-lo)),'state'))
    for name,entry,blob in EXTRA_CODE:
        at=append(blob)
        spans.append((name,entry,entry+len(blob),at,'adapter'))
        queue.append((name,entry,entry+len(blob),at,
                      list(B.M.S.disasm(blob,entry,entry,entry+len(blob)))))
    for target,blob in EXTRA_DATA.items():bindings[target]=append(blob)
    if DIRECTORY_AUX:
        bindings[0x402b662c]=append(b'\xff'*4)
        bindings[0x44e6ba08]=append(bytes(256))
        # mkdir's character classification uses signed char indices.
        ctype=struct.unpack_from('>I',donor,0x4030c434-B.BASE)[0]
        ctype_at=append(donor[ctype-B.BASE-128:ctype-B.BASE+256])
        bindings[0x4030c434]=append(B.BE(ctype_at+128))
    def resolve(target):
        for _,lo,hi,at,_ in spans:
            if lo<=target<hi:return at+target-lo
        for span in inherited_spans:
            lo,hi=int(span['donor'],16),int(span['end'],16)
            if lo<=target<hi:return int(span['runtime'],16)+target-lo
        if target in bindings:return bindings[target]
        if 0x401ed000<=target<0x40300000:
            end=donor.index(0,target-B.BASE)+1; blob=donor[target-B.BASE:end]
            assert len(blob)<512 and all(v==0 or 32<=v<127 for v in blob),('unresolved data',hex(target),blob[:32])
            bindings[target]=append(blob);return bindings[target]
        assert 0x40000400<=target<0x401ed000,('unresolved state',hex(target))
        end,rows=B.M.function(donor,target);blob=donor[target-B.BASE:end-B.BASE]
        refs=list(B.M.operands(rows,extra_ranges=[(lo,hi) for _,lo,hi in EXTRA_STATE]))
        external=[]
        for pc,hx,mn,ops in rows:
            match=re.search(r'\$([0-9a-f]{8})\(pc\)',ops)
            if match and not target<=int(match[1],16)<end:external.append(int(match[1],16))
        mask=bytearray(b'\1'*len(blob))
        for operand,_,_,_ in refs:mask[operand-target:operand-target+4]=bytes(4)
        pattern=b''.join(re.escape(bytes([v])) if keep else b'.' for v,keep in zip(blob,mask))
        allow_relative=INFER_NATIVE_LIBRARY_OPERANDS and target>=0x40100000
        hits=[] if external and not allow_relative else [B.BASE+m.start() for m in re.finditer(pattern,native,re.S) if m.start()%2==0]
        # Native code must also agree with every established dependency.
        compatible=[hit for hit in hits if all(value not in bindings or struct.unpack_from('>I',native,hit-B.BASE+operand-target)[0]==bindings[value] for operand,value,_,_ in refs)]
        compatible=[hit for hit in compatible if all(value not in bindings or value+hit-target==bindings[value] for value in external)]
        if external and len(compatible)!=1:
            compatible=[]  # Equal bytes at different PCs can call different peers.
        inferred=[]
        if INFER_NATIVE_LIBRARY_OPERANDS and target>=0x40100000 and len(compatible)==1:
            hit=compatible[0]
            for operand,value,_,_ in refs:
                new=struct.unpack_from('>I',native,hit-B.BASE+operand-target)[0]
                if value not in bindings:
                    bindings[value]=new;inferred.append(dict(donor=hex(value),native=hex(new)))
            for value in external:
                new=value+hit-target
                if value not in bindings:
                    bindings[value]=new;inferred.append(dict(donor=hex(value),native=hex(new),kind='unchanged PC-relative operand'))
        hits=[hit for hit in compatible if all(value in bindings for _,value,_,_ in refs)]
        if hits:
            assert len({native[h-B.BASE:h-B.BASE+len(blob)] for h in hits})==1,('ambiguous twin',hex(target),hits)
            bindings[target]=hits[0]
            evidence.append(dict(donor=hex(target),end=hex(end),native=hex(hits[0]),kind='Complete code twin with bound operands',inferred_operands=inferred))
        else:
            bindings[target]=add_code(f'helper_{target:08x}',target,end,rows)
        return bindings[target]
    # Typeinfo and vtable pointers are typed words, never blanket integer scans.
    for _,lo,hi,at,kind in list(spans):
        if kind!='data':continue
        for pc in range(lo,hi,4):
            target=struct.unpack_from('>I',payload,at-base+pc-lo)[0]
            if 0x40000000<=target<0x48000000:
                dest=resolve(target);struct.pack_into('>I',payload,at-base+pc-lo,dest)
                edits.append(dict(donor=hex(pc),runtime=hex(at+pc-lo),target=hex(target),binding=hex(dest),kind='typed pointer'))
    for name,lo,hi,at,rows in queue:
        for operand,target,_,_ in B.M.operands(rows,extra_ranges=[(lo,hi) for _,lo,hi in EXTRA_STATE]):
            try:dest=resolve(target)
            except Exception as error:
                error.add_note(f'{name}: operand {operand:#x} -> {target:#x}')
                chain=[];pending=[lo];seen=set()
                while pending and len(chain)<16:
                    current=pending.pop(0)
                    if current in seen:continue
                    seen.add(current)
                    for edit in edits:
                        if int(edit['target'],16)!=current:continue
                        site=int(edit['donor'],16)
                        parent=next((s for s in spans if s[1]<=site<s[2]),None)
                        if parent:
                            chain.append(dict(caller=parent[0],site=hex(site),callee=hex(current)))
                            pending.append(parent[1])
                (out/'link-progress.json').write_text(json.dumps(dict(error=str(error),
                    function=name,operand=hex(operand),target=hex(target),callers=chain),indent=2)+'\n')
                raise
            struct.pack_into('>I',payload,at-base+operand-lo,dest)
            edits.append(dict(donor=hex(operand),runtime=hex(at+operand-lo),target=hex(target),binding=hex(dest),kind='absolute operand'))
        for pc,hx,mn,ops in rows:
            match=re.search(r'\$([0-9a-f]{8})(\(pc\))?',ops)
            branch=mn.split('.')[0] in B.M.BRANCHES
            if not match or not(match[2] or branch):continue
            target=int(match[1],16)
            if lo<=target<hi:continue
            assert mn.split('.')[0] in ('jsr','lea','pea') or branch,(hex(pc),mn,ops)
            dest=resolve(target)
            if RESERVE_VENEERS:
                veneer=reserved_veneers[(at,pc)]
                payload[veneer-base:veneer-base+6]=b'\x4e\xf9'+B.BE(dest)
            else:veneer=append(b'\x4e\xf9'+B.BE(dest))
            width=len(bytes.fromhex(hx));delta=veneer-(at+pc-lo+2)
            # Class-relative branches are all internal. Out-of-class short
            # tails require a local veneer, not silently truncated offsets.
            if width==2:
                assert -128<=delta<128 and delta!=0,(hex(pc),delta)
                struct.pack_into('>b',payload,at-base+pc-lo+1,delta)
            else:
                assert width==4 and -32768<=delta<32768,(hex(pc),delta)
                struct.pack_into('>h',payload,at-base+pc-lo+2,delta)
            edits.append(dict(donor=hex(pc),runtime=hex(at+pc-lo),target=hex(target),binding=hex(dest),veneer=hex(veneer),kind='relative code operand'))
    payload.extend(bytes(-len(payload)%4));assert base+len(payload)<=LIMIT
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),runtime_limit=hex(LIMIT),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE))
    doc[COMPONENT]=dict(methods={k:hex(resolve(v)) for k,v in METHODS.items()},
            edits=edits,evidence=evidence,spans=[dict(name=n,donor=hex(lo),end=hex(hi),runtime=hex(at),kind=k) for n,lo,hi,at,k in spans],
            connected_to_picker=False,layout=f'Private runtime cap {LIMIT:#x} follows existing recovered-owner layout; no hardware stack high-water proof')
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=doc[COMPONENT]['methods']),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    build(parser.parse_args().output)
