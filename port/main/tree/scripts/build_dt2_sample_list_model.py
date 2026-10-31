#!/usr/bin/env python3
"""Link native DT2 list rebuilding and pool-name callbacks with a real Menu.

The pool directory has the donor's 1024 packed slots (eight OFF positions).
Loading/restoring sample identities is not yet connected. Its in-use query
is a named diagnostic stop until the project sample references are ported.
No menu is exposed to hardware by this component.
"""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_sample_list as L

M,R,T,BASE,BE=L.M,L.R,L.T,L.BASE,L.BE
INPUT=T.ROOT/'output/dn2-research/dt2-sample-list-20261009'
SHA='16eeca8ebbcad0dcc2a1a86289f90438b817b04faddf21223acbe0f1a7214335'
LIMIT=0x47a64000
CODE=[('row_manager',0x4001ded8,0x4001df34),
      ('row_name',0x4001dfbe,0x4001e0ac),
      ('rebuild',0x4001e31a,0x4001e4ae),
      ('pool_directory',0x400163b0,0x40016590),
      ('pool_lifetime',0x4019977c,0x401997b8),
      ('directory_lifetime',0x401554ac,0x401554ea),
      ('pool_lookup',0x401537a8,0x401537d0)]
DATA=[('pool_rtti',0x401ed484,0x401ed4d8),
      ('directory_rtti',0x4022576c,0x402257bc),
      ('row_rtti',0x401ee45c,0x401ee464)]
CODE_HOLES=[]
EXTRA_BINDINGS={}
IMPORTS={0x40016768:'Project sample-in-use query'}
RTTI_MATCHES=[(0x4021cb7c,0x40206548),(0x4021dae0,0x402074ac),(0x401ec32c,0x401d3b54)]


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert T.SHA(raw)==SHA
    donor=M.S.DONOR.read_bytes();assert T.SHA(donor)==M.S.SHA
    native=M.RECIPIENT.read_bytes()
    mapping=json.loads((M.OUT/'map.json').read_text())
    assert T.SHA(native)==mapping['recipient_sha256']
    receipt=json.loads((INPUT/'build-receipt.json').read_text())
    copy=receipt['runtime_copy'];src=int(copy['source'],16);base=int(copy['destination'],16)
    payload=bytearray(raw[src-BASE:src-BASE+copy['bytes']]);spans=[];bindings={};evidence=[]
    out.mkdir(parents=True,exist_ok=False)
    def append(blob):
        payload.extend(bytes(-len(payload)%4));at=base+len(payload);payload.extend(blob);return at
    for name,lo,hi in CODE+DATA:
        at=append(donor[lo-BASE:hi-BASE]);spans.append((name,lo,hi,at))
    # The pool owns full donor-sized tables, initialized to non-null empty
    # strings. A future loader publishes names/lengths here with sample IDs.
    empty=append(b'\0');names=append(BE(empty)*1024);sizes=append(bytes(4096))
    bindings.update({0x405bc768:names,0x405ba768:sizes})
    unresolved=[]
    for target,meaning in IMPORTS.items():
        fault=append(bytes.fromhex('4afc60fc'))
        bindings[target]=fault
        unresolved.append(dict(donor=hex(target),meaning=meaning,stop=hex(fault)))
    proven={int(x['donor'],16):x for x in mapping['functions']}
    for x in mapping['functions']:
        if len(x.get('dn2_twins',[]))==1:bindings[int(x['donor'],16)]=int(x['dn2_twins'][0],16)
        for pair in x.get('operands',[]):
            target=int(pair['donor'],16);dest=int(pair['dn2'],16)
            if target in bindings:assert bindings[target]==dest
            bindings[target]=dest
    # Reuse all explicitly established renderer/common string bindings.
    for pair in receipt['sample_list']['patches']:
        old,new=int(pair['before'],16),int(pair['after'],16)
        if old in bindings and old<0x40200000:
            assert bindings[old]==new,(hex(old),hex(bindings[old]),hex(new))
        bindings[old]=new
    # Native typeinfo vtables identified from shared base types by name and
    # their actual typeinfo records. These preserve the GNU C++ RTTI ABI.
    for old,new in RTTI_MATCHES:
        ov,on=struct.unpack_from('>II',donor,old-BASE)
        nv,nn=struct.unpack_from('>II',native,new-BASE)
        os=donor[on-BASE:donor.index(0,on-BASE)+1]
        ns=native[nn-BASE:native.index(0,nn-BASE)+1]
        assert os==ns
        bindings[ov]=nv;bindings[old]=new
        evidence.append(dict(kind='native RTTI type-name match',donor=hex(old),dn2=hex(new),name=os[:-1].decode()))
    bindings.update(EXTRA_BINDINGS)

    def code_rows(lo,hi):
        intervals=[(lo,hi)]
        for a,b in CODE_HOLES:
            intervals=[part for x,y in intervals for part in ((x,min(y,a)),(max(x,b),y)) if part[0]<part[1]]
        return [row for x,y in intervals for row in M.S.disasm(donor,BASE,x,y)]

    def mapped(target):
        for _,lo,hi,at in spans:
            if lo<=target<hi:return at+target-lo
        if target in bindings:return bindings[target]
        # Every remaining rodata reference here is a bounded C string.
        if 0x401ee000<=target<0x40260000 and target not in (0x401e30d0,):
            off=target-BASE;end=donor.index(0,off)+1;blob=donor[off:end]
            assert len(blob)<512 and all(v==0 or 32<=v<127 for v in blob),(hex(target),blob[:40])
            bindings[target]=append(blob);return bindings[target]
        # Resolve only complete byte-identical native implementations. No
        # address masking for previously ambiguous tiny utility routines.
        end,rows=M.function(donor,target);blob=donor[target-BASE:end-BASE]
        ops=list(M.operands(rows));mask=bytearray(b'\1'*len(blob))
        for at,_,_,_ in ops:mask[at-target:at-target+4]=bytes(4)
        pattern=b''.join(re.escape(bytes([b])) if keep else b'.' for b,keep in zip(blob,mask))
        hits=[BASE+x.start() for x in re.finditer(pattern,native,re.S) if x.start()%2==0]
        if len(hits)>1 and ops:
            for _,value,_,_ in ops:
                if value not in bindings and 0x40000400<=value<0x401ee000:
                    mapped(value)
            hits=[hit for hit in hits if all(value not in bindings or
                  struct.unpack_from('>I',native,hit-BASE+at-target)[0]==bindings[value]
                  for at,value,_,_ in ops)]
            if hits and len({native[h-BASE:h-BASE+len(blob)] for h in hits})==1:
                hits=hits[:1]  # literal identical copies have the same behavior
        if not ops and hits:
            dest=hits[0]
        else:
            assert len(hits)==1,('unresolved',hex(target),len(blob),len(hits))
            dest=hits[0]
        bindings[target]=dest
        evidence.append(dict(kind='complete native code twin',donor=hex(target),end=hex(end),dn2=hex(dest)))
        return dest

    edits=[]
    for name,lo,hi,at in spans[:len(CODE)]:
        rows=code_rows(lo,hi)
        for operand,target,mn,ops in M.operands(rows):
            dest=mapped(target);struct.pack_into('>I',payload,at-base+operand-lo,dest)
            edits.append(dict(component=name,operand=hex(operand),before=hex(target),after=hex(dest)))
        # Relative references within one copied span retain exact bytes.
        # All other PC-relative operands must be explicitly relocated.
        for pc,hx,mn,ops in rows:
            if '(pc)' not in ops:continue
            match=re.search(r'\$([0-9a-f]{8})\(pc\)',ops);assert match,(hex(pc),ops)
            target=int(match[1],16)
            if lo<=target<hi:continue
            dest=mapped(target);delta=dest-(at+pc-lo+2)
            assert -32768<=delta<32768,(hex(pc),hex(dest),delta)
            struct.pack_into('>h',payload,at-base+pc-lo+2,delta)
            edits.append(dict(component=name,operand=hex(pc+2),before=hex(target),after=hex(dest),relative=True))
    for name,lo,hi,at in spans[len(CODE):]:
        for oldat in range(lo,hi,4):
            value=struct.unpack_from('>I',donor,oldat-BASE)[0]
            if 0x40000000<=value<0x48000000:
                dest=mapped(value);struct.pack_into('>I',payload,at-base+oldat-lo,dest)
                edits.append(dict(component=name,operand=hex(oldat),before=hex(value),after=hex(dest)))
    payload.extend(bytes(-len(payload)%4));assert base+len(payload)<=LIMIT
    image=bytearray(raw[:src-BASE])+payload;boot=BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+BE(boot)
    methods={name:hex(at) for name,_,_,at in spans}
    methods.update(pool_name=hex(mapped(0x400164e0)),pool_empty=hex(mapped(0x400163c6)),
                   pool_init=hex(mapped(0x40016576)),pool_destroy=hex(mapped(0x4019977c)))
    receipt.update(baseline_sha256=SHA,main_sha256=T.SHA(image),bytes=len(image),
                   runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=T.SHA(payload),runtime_limit=hex(LIMIT),
                   bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-BASE),
                   pool_model=dict(methods=methods,names=hex(names),sizes=hex(sizes),empty=hex(empty),
                                   edits=edits,evidence=evidence,unresolved=unresolved,
                                   menu_constructor=hex(mapped(0x40114ede)),menu_destructor=hex(mapped(0x40115042)),
                                   slots=1024,loaded_samples=0),
                   flash_ready=False)
    (out/'runtime.bin').write_bytes(payload);(out/'main-os.bin').write_bytes(image)
    for name,lo,hi,at in spans[:len(CODE)]:
        blob=bytes(payload[at-base:at-base+hi-lo]);(out/(name+'.bin')).write_bytes(blob)
        (out/(name+'.asm')).write_text('\n'.join(f'{a:08x} -> {at+a-lo:08x} {h:24} {m:10} {o}' for a,h,m,o in code_rows(lo,hi))+'\n')
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=receipt['main_sha256'],runtime_bytes=len(payload),methods=methods,unresolved=unresolved),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
