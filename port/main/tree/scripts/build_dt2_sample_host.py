#!/usr/bin/env python3
"""Link original DT2 sample RPC dispatcher (not yet install its live hook)."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
import build_dt2_waveform_events as W
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-file-output-stream-20261010'
SHA='046e12deeac1062a23fa7329a09bca9ca386c3e74631d4251ec045adecf9bcc0'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_host';L.LIMIT=0x47ab0000
    L.CODE=[('dispatch',0x401283e2,0x4012aa04),('error_text',0x40127be8,0x40127d18),
            ('file_query_helpers',0x40158e9e,0x40159098),
            ('writer_owner',0x40127a56,0x40127b74),('writer_teardown',0x40127d5c,0x40127df4),
            ('writer_transfer',0x40127f28,0x401281bc)]
    L.DATA=[('handler_lambda_types',0x4021edd4,0x4021ee0c),
            ('writer_types',0x4021f04c,0x4021f070),('writer_vtables',0x4021f3b8,0x4021f3ec)]
    L.EXTRA_STATE=[('sample_status',0x405b135c,0x405b1360)]
    L.EXTRA_CODE=[];L.EXTRA_DATA={};L.EXTRA_TYPED_DATA=[]
    L.EXTRA_SPANS=[];bindings={}
    for part in doc.values():
        if not isinstance(part,dict) or 'spans' not in part:continue
        L.EXTRA_SPANS[0:0]=part['spans']
        for e in part.get('edits',[]):
            if 'target' in e and 'binding' in e:bindings[int(e['target'],16)]=int(e['binding'],16)
    bindings.update(W.BINDINGS)
    # RTTI is reused only for the same named type and matching compiler RTTI
    # category. This binds dynamic_cast identities, not request field layouts.
    type_evidence=[]
    for ti in range(0x401ec000,0x4022593c,4):
        kind,name=struct.unpack_from('>II',donor,ti-B.BASE)
        if kind not in (0x402258b8,0x4022593c,0x402258fc):continue
        if not B.BASE<=name<B.BASE+len(donor):continue
        text=donor[name-B.BASE:].split(b'\0')[0]
        if not text or len(text)>200 or any(c<32 or c>126 for c in text):continue
        hits=[];pos=0
        while (pos:=native.find(text+b'\0',pos))>=0:
            ptr=struct.pack('>I',pos+B.BASE);ref=0
            while (ref:=native.find(ptr,ref))>=0:
                if ref%4==0 and ref>=4 and struct.unpack_from('>I',native,ref-4)[0]==bindings.get(kind):hits.append(B.BASE+ref-4)
                ref+=1
            pos+=1
        if len(hits)==1:
            bindings[ti]=hits[0];type_evidence.append(dict(donor=hex(ti),native=hex(hits[0]),name=text.decode()))
    # Reuse same-type protocol vtables: five entries for shared ownership,
    # four for messages. Sequence-ID getters must match byte-for-byte. Field
    # layout/codec composition remains a separate gate before live insertion.
    vtable_evidence=[]
    for row in type_evidence:
        owner=row['name'].startswith('St23_Sp_counted_ptr_inplaceIN8elektron')
        message=row['name'].startswith('N8elektron') and 'MidiRpc' in row['name']
        if not (owner or message):continue
        old,new=int(row['donor'],16),int(row['native'],16)
        dpos=donor.find(b'\0'*4+struct.pack('>I',old));npos=native.find(b'\0'*4+struct.pack('>I',new))
        if dpos<0 or npos<0:continue
        assert donor.find(b'\0'*4+struct.pack('>I',old),dpos+1)<0
        assert native.find(b'\0'*4+struct.pack('>I',new),npos+1)<0
        oldvt,newvt=B.BASE+dpos+8,B.BASE+npos+8
        count=5 if owner else 4
        methods=struct.unpack_from('>'+str(count)+'I',donor,dpos+8);counterparts=struct.unpack_from('>'+str(count)+'I',native,npos+8)
        assert all(0x40000400<=x<0x401ec000 for x in methods+counterparts)
        if message:
            end,_=B.M.function(donor,methods[2]);size=end-methods[2]
            assert donor[methods[2]-B.BASE:end-B.BASE]==native[counterparts[2]-B.BASE:counterparts[2]-B.BASE+size],row['name']
        bindings[oldvt]=newvt
        vtable_evidence.append(dict(donor=hex(oldvt),native=hex(newvt),type=row['name'],
            methods=[hex(x) for x in methods],native_methods=[hex(x) for x in counterparts],
            field_layout_verification_pending=True))
    L.EXTRA_BINDINGS=bindings;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True
    L.INFER_NATIVE_LIBRARY_OPERANDS=True;L.METHODS={'dispatch':0x401283e2}
    # Existing stock ownership audit recovers the heap and all fixed RTOS
    # stacks below this reservation. The cap is a local allocation limit, not
    # a claimed hardware stack floor; physical high-water remains unmeasured.
    ownership=json.loads((B.T.ROOT/'output/dn2-research/combined-ram-ownership-20261008/result.json').read_text())
    start=int(doc['runtime_copy']['destination'],16)
    for region in ownership['heap_regions']+ownership['task_stacks']:
        assert not (start<int(region['end'],16) and int(region['start'],16)<L.LIMIT)
    assert L.LIMIT<int(ownership['reset_stack_top'],16)
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    # SourceView previously imported this helper with the DT2 serialized-kit
    # mask offset. Its complete native body differs by exactly this word.
    lo,hi,new=0x4003618c,0x400361c6,0x40031274
    original=bytearray(donor[lo-B.BASE:hi-B.BASE]);correct=native[new-B.BASE:new-B.BASE+hi-lo]
    assert original[0x2a:0x2c]==bytes.fromhex('552e') and correct[0x2a:0x2c]==bytes.fromhex('5cda')
    original[0x2a:0x2c]=correct[0x2a:0x2c];assert original==correct
    shared=next(int(s['runtime'],16) for s in doc['source_view']['spans'] if s['donor']==hex(lo))
    copy=doc['runtime_copy'];offset=int(copy['source'],16)-B.BASE+shared-int(copy['destination'],16)
    image=bytearray((out/'main-os.bin').read_bytes())
    assert image[offset:offset+hi-lo]==donor[lo-B.BASE:hi-B.BASE]
    image[offset:offset+hi-lo]=correct
    (out/'main-os.bin').write_bytes(image)
    runtime=bytes(image[int(copy['source'],16)-B.BASE:int(copy['source'],16)-B.BASE+copy['bytes']])
    (out/'runtime.bin').write_bytes(runtime)
    doc['main_sha256']=B.T.SHA(image);doc['runtime_sha256']=B.T.SHA(runtime)
    doc['sample_host'].update(typeinfo_evidence=type_evidence,vtable_evidence=vtable_evidence,live_hook_installed=False,
        shared_layout_repairs=[dict(method=hex(shared),donor=hex(lo),native=hex(new),
            field='serialized kit MIDI-track mask',before='0x552e',after='0x5cda',
            evidence='Complete58-byte native body; this is its only differing operand.')],
        limits=['Owner lifecycle, request layout adaptations and application callbacks are pending.',
                'Cap47AB0000 extends recovered-owner reservation; no hardware stack high-water claim.'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(final_main_sha256=doc['main_sha256'],shared_layout_repairs=doc['sample_host']['shared_layout_repairs']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
