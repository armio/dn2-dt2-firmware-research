#!/usr/bin/env python3
"""WIP: assemble the complete original Source view with native DN2 base UI."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-events-20261009'
SHA='b0612a6e7c33186657101f3dd371b8a5d11352151dadbf644d9519ccc5e4ea4d'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_view';L.LIMIT=0x47aa0000
    L.CODE=[('source_init',0x4001753a,0x40017728),('source_tick',0x40017a40,0x40017b50),
            ('source_destructors',0x40199de0,0x40199eb2)]
    L.DATA=[('source_constructor_callbacks',0x401ed830,0x401ed840),
            ('source_type',0x401ed84c,0x401ed858),('source_vtables',0x401ed880,0x401ed9d8),
            ('source_machine_names',0x4020eb68,0x4020ebbc)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[('source_status_text',0x40965b8c,0x40965bec),
                                 ('source_tick_counter',0x40965bec,0x40965bf0)]
    L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[];binds={}
    for key in ('sample_manager','pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls','source_draw','source_browser','source_encoder','source_dialogs','grid_actions','slice_create_dialog','manual_slice_editor','source_events'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:binds[int(e['target'],16)]=int(e['binding'],16)
    binds.update({int(k,16):int(v,16) for k,v in doc['source_page_access']['source_bindings'].items()})
    binds[0x4005063e]=int(doc['source_browser']['methods']['source_browser_machine'],16)
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes();evidence=[]
    # Clipboard operations receive the native page ID from the retained base
    # view. Keep DN2's own Project/Sound storage and undo implementations.
    for old,new in [(0x40049bf2,0x40045d66),(0x40049cbc,0x40045e30),
                    (0x4004a0e6,0x40046262),(0x4004632a,0x40042608),
                    (0x4004a03e,0x400461ba),(0x4004a222,0x4004639e),
                    (0x400c8826,0x400c2474),
                    (0x401e5f2e,0x401ccb68),(0x401e5e8a,0x401ccac4),
                    (0x40118ee8,0x4011a85c),
                    (0x40199f22,0x4018a5c8),(0x40199fda,0x4018a5c8),
                    (0x40199f94,0x4018a63a),(0x4019a04c,0x4018a63a),
                    (0x400f541c,0x400f6df8)]:
        end,rows=B.M.function(donor,old)
        x=bytearray(donor[old-B.BASE:end-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+len(x)])
        pairs=[]
        for at,target,_,_ in B.M.operands(rows):
            dest=struct.unpack_from('>I',y,at-old)[0]
            x[at-old:at-old+4]=y[at-old:at-old+4]=bytes(4)
            pairs.append(dict(donor=hex(target),native=hex(dest)))
        for at,hx,mn,ops in rows:
            match=re.search(r'\$([0-9a-f]{8})\(pc\)',ops)
            if match:
                off=at-old+2;dest=new+off+struct.unpack_from('>h',y,off)[0]
                pairs.append(dict(donor='0x'+match[1],native=hex(dest),addressing='pc-relative'))
                x[off:off+2]=y[off:off+2]=bytes(2)
        if old==0x400c8826:
            assert x[1]==32 and y[1]==36  # Native parameter-page count.
            x[1]=y[1]=0
        assert x==y,hex(old)
        binds[old]=new
        evidence.append(dict(donor=hex(old),native=hex(new),bytes=end-old,
                             role='native page clipboard, metadata or string helper',operands=pairs))
    # Both constructors build the same MachineParameterPage object layout.
    old,new,end=0x4005f578,0x4005a2ea,0x4005f6bc
    x=bytearray(donor[old-B.BASE:end-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+len(x)]);pairs=[]
    for at,target,_,_ in B.M.operands(list(B.M.S.disasm(donor,B.BASE,old,end))):
        dest=struct.unpack_from('>I',y,at-old)[0];binds[target]=dest
        x[at-old:at-old+4]=y[at-old:at-old+4]=bytes(4)
        pairs.append(dict(donor=hex(target),native=hex(dest)))
    # The captured ActiveTrack callback is addressed relative to PC in each
    # image; its displacement changes independently of the absolute operands.
    at=0x4005f66c;offset=at-old
    assert x[offset:offset+2]==y[offset:offset+2]==bytes.fromhex('41fa')
    target=at+2+struct.unpack_from('>h',x,offset+2)[0]
    dest=new+offset+2+struct.unpack_from('>h',y,offset+2)[0]
    assert (target,dest)==(0x4005f328,0x4005a21a)
    binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest),addressing='pc-relative'))
    x[offset+2:offset+4]=y[offset+2:offset+4]=bytes(2)
    assert x==y
    binds[old]=new;evidence.append(dict(donor=hex(old),native=hex(new),bytes=end-old,operands=pairs))
    # Bind only methods inherited unchanged from the same named base class.
    def type_name(raw,at):
        addr=struct.unpack_from('>I',raw,at+4-B.BASE)[0]-B.BASE
        return raw[addr:raw.index(0,addr)]
    # Both original factories create the same 160-byte PopupWindow in a
    # 176-byte shared owner; DN2's equivalent factory accepts the same text.
    popup_old=struct.unpack_from('>I',donor,0x401ed9fc-4-B.BASE)[0]
    popup_vt=struct.unpack_from('>I',native,0x4018a5c8+0x34-B.BASE)[0]
    popup_new=struct.unpack_from('>I',native,popup_vt-4-B.BASE)[0]
    assert type_name(donor,popup_old)==type_name(native,popup_new)==b'St23_Sp_counted_ptr_inplaceI11PopupWindowSaIS0_ELN9__gnu_cxx12_Lock_policyE0EE'
    oldvt,newvt=0x401f6a94,0x401df6f0
    oldtype=struct.unpack_from('>I',donor,oldvt-4-B.BASE)[0]
    newtype=struct.unpack_from('>I',native,newvt-4-B.BASE)[0]
    assert type_name(donor,oldtype)==type_name(native,newtype)==b'24MachineParameterPageView'
    binds[oldtype]=newtype;inherited=[]
    for offset in range(0,0xf0,4):
        target=struct.unpack_from('>I',donor,oldvt+offset-B.BASE)[0]
        actual=struct.unpack_from('>I',donor,0x401ed888+offset-B.BASE)[0]
        dest=struct.unpack_from('>I',native,newvt+offset-B.BASE)[0]
        if target==actual:
            binds[target]=dest;inherited.append(dict(offset=hex(offset),donor=hex(target),native=hex(dest)))
    # Source destruction ends in its native base destructor.
    binds[0x40199d26]=struct.unpack_from('>I',native,newvt-B.BASE)[0]
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'init':0x4001753a,'tick':0x40017a40,'destroy':0x40199de0}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    doc['source_view'].update(native_body_evidence=evidence,inherited_base_methods=inherited)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
