#!/usr/bin/env python3
"""Link original DT2 SampleManager against the transplanted filesystem and pool."""
from pathlib import Path
import argparse,json,struct,re,tempfile
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-browser-popup-20261009'
SHA='f9185ea626b6d9ed07f0f8d36fe5a6478c5ebb1b0b6e931f6f6f95521d079fae'
# Explicit component-link imports. They deliberately trap, never return fake
# success. No image containing these imports may be presented as flash-ready.
PENDING_SERVICES={
    0x4004b502:'project_load_sample_identity: donor ProjectSettings*,16-byte identity*,slot; returns success',
    0x40050daa:'sound_assign_sample: Sound*,slot; updates sample field and parameter notification',
    0x40043c1c:'project_used_sample_bitmap: hidden A0 output128,Project*; scans saved/live kits, locks, preset pool and OFF slots',
    0x4004b710:'project_sample_identity: hidden A0 output16,ProjectSettings*,slot; reads persistent sample identity',
    0x4004b794:'project_unload_sample: ProjectSettings*,slot; clears identity, unloads audio slot and emits project change',
    0x40153b1e:'preview_metadata_flag: getter reads the loaded-preview header flag; requires preview bridge',
    0x40153e36:'prepare_preview_identity: identity*; streams preview into donor DSP slot1024; needs DN2 audio-memory bridge',
    0x401537e0:'sample_memory_free: bytes available to the sample allocator; requires DN2 allocator accounting',
    0x4015381e:'sample_memory_total: total sample memory; donor 400MiB constant is not a DN2 capacity',
    0x4015444e:'sample_memory_fit: identity*; donor allocator fit/compaction assessment (0,1,2)',
}



def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    bindings={}
    for row in doc['browser_popup']['native_anchors']:
        bindings[int(row['donor'],16)]=int(row['dn2'],16)
        for pair in row['operands']:bindings[int(pair['donor'],16)]=int(pair['dn2'],16)
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    # The identical native panel/window constructors establish these vtables;
    # their ABI typeinfo pointer is the word immediately before the address point.
    for old,new in [(0x401fdc1c,0x401e680c),(0x4021c738,0x40206104)]:
        old_type=struct.unpack_from('>I',donor,old-4-B.BASE)[0]
        new_type=struct.unpack_from('>I',native,new-4-B.BASE)[0]
        def name(raw,at):
            p=struct.unpack_from('>I',raw,at+4-B.BASE)[0]-B.BASE
            return raw[p:raw.index(0,p)]
        assert name(donor,old_type)==name(native,new_type)
        bindings[old_type]=new_type
    # Corresponding font constructors have identical instruction structure;
    # every object uses the established native BitmapFont vtable.
    for old,new in zip(range(0x401d0e86,0x401d0fee,24),range(0x401b9d1c,0x401b9e84,24)):
        x=donor[old-B.BASE:old-B.BASE+24];y=native[new-B.BASE:new-B.BASE+24]
        assert x[:6]==bytes.fromhex('203c4021cb58') and y[:6]==bytes.fromhex('203c40206524')
        assert x[6:8]==y[6:8]==b'\x23\xc0' and x[12:14]==y[12:14]==b'\x20\x3c' and x[18:20]==y[18:20]==b'\x23\xc0'
        # Preserve this historical stage. The later sample-manager-font-fix
        # stage binds the direct Font descriptor without changing this layout.
        for offset in (8,20):bindings[struct.unpack_from('>I',x,offset)[0]]=struct.unpack_from('>I',y,offset)[0]
    # Distinguish identical throw-helper instruction bodies by exception RTTI.
    name=b'St12out_of_range\0';name_at=native.index(name)+B.BASE
    refs=[m.start()+B.BASE-4 for m in re.finditer(re.escape(struct.pack('>I',name_at)),native)]
    assert len(refs)==1 and struct.unpack_from('>I',native,refs[0]-B.BASE)[0]==0x4020ef38
    assert donor[0x4025e1f7-B.BASE:0x4025e1f7-B.BASE+len(name)]==name
    bindings[0x4022610c]=refs[0]
    # The stock DesignerVerticalMenuView draw method also uses the status icon.
    for entry in (0x4009021a,0x40110bb8,0x40116394,0x401e46fc,0x40117990,0x40114e06,0x400f0c18,0x40198a16,0x40118ee8,0x4019ccdc,0x40001608,0x4000172a,0x401121d6,0x401995e4,0x400d6726):
        end,rows=B.M.function(donor,entry);blob=donor[entry-B.BASE:end-B.BASE]
        refs=list(B.M.operands(rows));mask=bytearray(b'\1'*len(blob))
        for operand,_,_,_ in refs:mask[operand-entry:operand-entry+4]=bytes(4)
        pattern=b''.join(re.escape(bytes([v])) if keep else b'.' for v,keep in zip(blob,mask))
        hits=[B.BASE+m.start() for m in re.finditer(pattern,native,re.S) if m.start()%2==0]
        hits=[h for h in hits if all(target not in bindings or struct.unpack_from('>I',native,h-B.BASE+operand-entry)[0]==bindings[target] for operand,target,_,_ in refs)]
        assert hits and len({native[h-B.BASE:h-B.BASE+len(blob)] for h in hits})==1,(hex(entry),hits)
        dest=hits[0];bindings[entry]=dest
        for operand,target,_,_ in refs:
            value=struct.unpack_from('>I',native,dest-B.BASE+operand-entry)[0]
            if target in bindings:assert bindings[target]==value,(hex(target),hex(value))
            bindings[target]=value
        for pc,hx,mn,ops in rows:
            match=re.search(r'\$([0-9a-f]{8})\(pc\)',ops)
            if match:
                target=int(match[1],16)
                if not entry<=target<end:bindings[target]=target+dest-entry
    abi_evidence=[]
    # DN2 has four more LED entries: use its actual manager, allocation and
    # setter, with explicit structure-size/array-offset differences.
    for entry,dest,changes in [(0x400307da,0x4002c212,{0x54:(b'\xfb\x9c',b'\xfc\x40')}),
                               (0x40199926,0x4018aabc,{0x12:(b'\x02\x80',b'\x02\xb0')}),
                               (0x400308e0,0x4002c318,{0x36:(b'\x00\xf0',b'\x01\x00'),0x42:(b'\x00\xf0',b'\x01\x00')})]:
        end,rows=B.M.function(donor,entry)
        x=bytearray(donor[entry-B.BASE:end-B.BASE]);y=bytearray(native[dest-B.BASE:dest-B.BASE+len(x)])
        for offset,(old,new) in changes.items():
            assert x[offset:offset+len(old)]==old and y[offset:offset+len(new)]==new
            x[offset:offset+len(old)]=y[offset:offset+len(new)]=bytes(len(old))
        for operand,target,_,_ in B.M.operands(rows):
            offset=operand-entry;value=struct.unpack_from('>I',y,offset)[0]
            if target in bindings:assert bindings[target]==value,(hex(target),hex(value))
            bindings[target]=value;x[offset:offset+4]=y[offset:offset+4]=bytes(4)
        assert x==y,hex(entry)
        native_rows=list(B.M.S.disasm(native,B.BASE,dest,dest+len(x)))
        for old_row,new_row in zip(rows,native_rows):
            old_pc=re.search(r'\$([0-9a-f]{8})\(pc\)',old_row[3])
            if old_pc:
                new_pc=re.search(r'\$([0-9a-f]{8})\(pc\)',new_row[3]);assert new_pc
                bindings[int(old_pc[1],16)]=int(new_pc[1],16)
        bindings[entry]=dest
        abi_evidence.append(dict(donor=hex(entry),native=hex(dest),bytes=len(x),
            changes={hex(k):[a.hex(),b.hex()] for k,(a,b) in changes.items()}))
    # Match bitmap initialization and both complete pixel/mask planes.
    for init,global_at,plane_bytes in [(0x4015c768,0x44f36f68,28),(0x401647de,0x44f35fc8,32),
                                       (0x40164298,0x44f361f0,120)]:
        icon=donor[init-B.BASE:init-B.BASE+28];mask=bytearray(b'\1'*len(icon))
        planes=[struct.unpack_from('>I',icon,offset)[0] for offset in (2,8)]
        assert struct.unpack_from('>I',icon,22)[0]==global_at
        for offset in (2,8,22):mask[offset:offset+4]=bytes(4)
        pattern=b''.join(re.escape(bytes([v])) if keep else b'.' for v,keep in zip(icon,mask))
        hits=[]
        for match in re.finditer(pattern,native,re.S):
            values=[struct.unpack_from('>I',native,match.start()+offset)[0] for offset in (2,8,22)]
            if all(donor[old-B.BASE:old-B.BASE+plane_bytes]==native[new-B.BASE:new-B.BASE+plane_bytes]
                   for old,new in zip(planes,values)):
                hits.append(values)
        assert len(hits)==1,(hex(global_at),hits)
        bindings[global_at]=hits[0][2]
    # Three complete native vector initializations use identical LED-id arrays.
    x=donor[0x4019eaa0-B.BASE:0x4019eafa-B.BASE]
    y=native[0x4018eed4-B.BASE:0x4018ef2e-B.BASE]
    rows=list(B.M.S.disasm(donor,B.BASE,0x4019eaa0,0x4019eafa))
    xm=bytearray(x);ym=bytearray(y)
    for operand,old,_,_ in B.M.operands(rows):
        offset=operand-0x4019eaa0;new=struct.unpack_from('>I',y,offset)[0]
        xm[offset:offset+4]=ym[offset:offset+4]=bytes(4)
        bindings[old]=new
    assert xm==ym
    for old,new,count in [(0x401f0a9c,0x401d963c,9),(0x401f0ac0,0x401d9660,16),(0x401f0b00,0x401d96a0,16)]:
        assert donor[old-B.BASE:old-B.BASE+count*4]==native[new-B.BASE:new-B.BASE+count*4]
    for old in (0x40966ab4,0x40966ac0,0x40966acc):
        for offset in (4,8):bindings[old+offset]=bindings[old]+offset
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_manager'
    L.LIMIT=0x47a78000
    L.DIRECTORY_AUX=False;L.EXTRA_BINDINGS=bindings;L.EXTRA_DATA={0x402294b3:b'AUTO-PREVIEW \x16\0',0x402294c2:b'AUTO-PREVIEW \x15\0',0x40229956:b'\x1d\0',0x40229958:b'\x07\0',0x4023f363:b'\x05\0',0x402299ac:b'RAM \x9b BANK %c\0'}
    L.EXTRA_DATA.update({entry:b'\x4a\xfc\x4e\x75' for entry in PENDING_SERVICES})
    L.EXTRA_DATA[0x4022949c]=b'ASSIGN SAMPLE \x9b %c%03d\0'
    # Original RAM meter's 22 Bitmap objects. Reproduce constructor401121D6
    # fields from initializer4015C242..4015C4AE and copy the actual DT2 planes.
    # This vector is static for the lifetime of the port; donor startup/dtor
    # are not registered on DN2. 46000000 is only a linker-side object label.
    meter_at=0x46000000;meter=bytearray()
    for index in range(22):
        plane=0x4030b97c+68*index
        meter.extend(struct.pack('>7I',0x4021cb40,17,29,1,plane,0x4030b938,0))
        L.EXTRA_DATA[plane]=donor[plane-B.BASE:plane-B.BASE+68]
    L.EXTRA_DATA[0x4030b938]=donor[0x4030b938-B.BASE:0x4030b97c-B.BASE]
    L.EXTRA_TYPED_DATA=[('ram_meter_frames',meter_at,bytes(meter)+bytes(4)),
                        ('ram_meter_vector',0x44f36ff0,struct.pack('>3I',meter_at,meter_at+len(meter),meter_at+len(meter)))]
    L.EXTRA_STATE=[('picker_path_buffer',0x40965df0,0x40965ef0),
                   ('manager_work_state',0x40965ef4,0x40966028),
                   ('browser_auto_preview',0x4099d5d1,0x4099d5d2)]
    preference_source=(B.T.ROOT/'scripts/asm/dt2_browser_preferences.S').read_text()
    with tempfile.TemporaryDirectory(prefix='dt2-manager-adapters-') as temp:
        preference_code=B.R.assemble(preference_source,0x400c12ae,Path(temp),'browser-preferences')
    L.EXTRA_CODE=[('auto_preview_set_adapter',0x400c12ae,preference_code)]
    L.INFER_NATIVE_LIBRARY_OPERANDS=True;L.RESERVE_VENEERS=True
    # Omit the translation-unit static singleton finalizer40026420..40026520;
    # its original registration belongs to DT2 startup, not this view lifetime.
    L.CODE=[('sample_manager_a',0x40023e84,0x40026420),
            ('sample_manager_b',0x40026520,0x4002a1b0),
            ('manager_lifetime',0x4019b426,0x4019b6ae),
            ('sample_picker_a',0x4001d1b0,0x4001d772),
            ('sample_picker_b',0x4001d80e,0x4001dd9a),
            ('fs_select_a',0x4001efac,0x4001f388),
            ('fs_select_lifetime',0x4019b92c,0x4019ba58),
            # Full filesystem unlink helper: the decoder labels register-only
            # 79c9 (MVZ.W A1,D4) as .word; it contains no address operand.
            ('filesystem_unlink_entry',0x4015691a,0x40156b24)]
    L.DATA=[('manager_types',0x401efecc,0x401f039c),
            ('led_base_type',0x401ed4e0,0x401ed4e8),
            ('led_base_vtable',0x401ed520,0x401ed534),
            ('directory_owner_type',0x401eec34,0x401eec40),
            ('directory_owner_vtable',0x401eed5c,0x401eed78),
            ('name_view_owner_type',0x401eec40,0x401eec4c),
            ('name_view_owner_vtable',0x401eed78,0x401eed94),
            ('progress_owner_type',0x401ecee8,0x401ecef4),
            ('progress_owner_vtable',0x401ecf60,0x401ecf7c),
            ('picker_types',0x401ee178,0x401ee33c),
            ('picker_owner_type',0x401ee4a4,0x401ee4b0),
            ('picker_owner_vtable',0x401ee5e0,0x401ee5fc),
            ('fs_select_types',0x401ee634,0x401ee758)]
    L.METHODS={'constructor':0x40029e7a,'destroy':0x4019b426,
               'draw':0x40023e84,'event':0x400295b6,'count':0x40023e98,
               'get_item':0x40025e6c,'view_event':0x40029e70,
               'factory':0x4019bb28,'picker_constructor':0x4001d80e,
               'picker_factory':0x4019d1b2}
    L.build(out)
    path=out/'build-receipt.json';result=json.loads(path.read_text())
    result['sample_manager']['native_abi_adaptations']=abi_evidence
    result['sample_manager']['unresolved_services']={hex(k):v for k,v in PENDING_SERVICES.items()}
    result['flash_ready']=False
    result['sample_manager']['pending_preferences']='AUTO-PREVIEW is private RAM state; persistence not yet connected'
    path.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    build(parser.parse_args().output)
