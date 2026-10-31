#!/usr/bin/env python3
"""Connect original DT2 project load/unload to DN2 identity companions."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-loader-20261009'
SHA='dd619f98a6637f2748aa65b0893f9a662ada45b10833011cba06f0ff41f8ab5b'
ENTRIES={'project_load':0x4004b502,'project_unload':0x4004b794,'find_free_slot':0x40016702}


def build(out):
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='project_sample_load';L.LIMIT=0x47a88000
    L.CODE=[(n,a,B.M.function(donor,a)[0]) for n,a in ENTRIES.items()]
    L.DATA=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.DIRECTORY_AUX=False
    L.EXTRA_DATA={0x402aafc8:b'\xff'*16}
    L.EXTRA_STATE=[('last_loaded_path',0x4099ca70,0x4099cb70)]
    L.EXTRA_SPANS=[];bindings={}
    for key in ('sample_manager','sample_allocator','sample_loader','pcm_pages'):
        L.EXTRA_SPANS.extend(doc[key]['spans'])
        for e in doc[key]['edits']:bindings[int(e['target'],16)]=int(e['binding'],16)
    for name,lo,hi in [('pool_directory',0x400163b0,0x40016590),
                       ('pool_lifetime',0x4019977c,0x401997b8),
                       ('directory_lifetime',0x401554ac,0x401554ea),
                       ('pool_lookup',0x401537a8,0x401537d0),
                       ('pool_rtti',0x401ed484,0x401ed4d8)]:
        L.EXTRA_SPANS.append(dict(donor=hex(lo),end=hex(hi),runtime=doc['pool_model']['methods'][name]))
    bindings.update({0x401360ac:0x40134490,0x401f41d8:0x401dcf30,
        0x4004b710:int(doc['project_sample_active']['methods']['sample_project_identity_get'],16)})
    # Preserve the native ProjectDataChangeInfo ABI used by ProjectSettings.
    for image,vt in ((donor,0x401f41d8),(native,0x401dcf30)):
        ti=struct.unpack_from('>I',image,vt-4-B.BASE)[0]
        name=struct.unpack_from('>I',image,ti+4-B.BASE)[0]
        assert image[name-B.BASE:name-B.BASE+24]==b'21ProjectDataChangeInfo\0'
    L.EXTRA_BINDINGS=bindings;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.RESERVE_VENEERS=True;L.METHODS=ENTRIES;L.build(out)
    result=json.loads((out/'build-receipt.json').read_text());cfg=result['project_sample_load']
    copy=result['runtime_copy'];base=int(copy['destination'],16)
    payload=bytearray((out/'runtime.bin').read_bytes());adapt=[]
    raw_get=int(result['project_sample_active']['methods']['sample_project_settings_raw'],16)
    # Replace only the raw-settings vtable dispatch. All donor slot selection,
    # load status, identity copy and change-notification branches remain intact.
    for name,entry in ENTRIES.items():
        if name=='find_free_slot':continue
        at=int(cfg['methods'][name],16);end,rows=B.M.function(donor,entry)
        calls=[pc for pc,h,m,o in rows if h=='20680028']
        assert len(calls)==3
        for pc in calls:
            offset=at-base+pc-entry
            assert payload[offset:offset+6]==bytes.fromhex('206800284e90')
            payload[offset:offset+6]=b'\x4e\xb9'+B.BE(raw_get)
            # The preceding load of the object's vtable is harmless and is
            # retained: the ProjectSettings object must be valid either way.
            adapt.append(dict(donor=hex(pc),runtime=hex(at+pc-entry),helper=hex(raw_get)))
    # The actual DN2 UI loop waits on this queue. Its31/32 cases currently
    # drop these events; later waveform-cache integration will fill them in.
    assert native[0x4002f178-B.BASE:0x4002f184-B.BASE]==bytes.fromhex('48794059d2144eb940001928')
    for event in (31,32):
        assert struct.unpack_from('>h',native,0x4002f19a-B.BASE+2*event)[0]==-34
    queue=next(int(s['runtime'],16) for s in result['sample_loader']['spans'] if s['name']=='notification_queue')
    assert payload[queue-base:queue-base+4]==bytes(4)
    struct.pack_into('>I',payload,queue-base,0x4059d214)
    sites=[]
    for name in ('project_load','project_unload'):
        old=ENTRIES[name];new=int(cfg['methods'][name],16)
        for e in result['sample_manager']['edits']:
            if int(e['target'],16)!=old:continue
            assert e['kind']=='absolute operand'
            offset=int(e['runtime'],16)-base
            assert payload[offset:offset+4]==B.BE(int(e['binding'],16))
            struct.pack_into('>I',payload,offset,new);e['binding']=hex(new)
            sites.append(dict(method=name,site=e['runtime']))
        del result['sample_manager']['unresolved_services'][hex(old)]
    image=bytearray((out/'main-os.bin').read_bytes());src=int(copy['source'],16)-B.BASE
    image[src:src+len(payload)]=payload
    result.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    cfg.update(connected_to_picker=True,settings_raw_adaptations=adapt,
        manager_call_sites=sites,notification_queue='0x4059d214',
        limits=['UI queue31/32 waveform-cache consumers remain absent',
                'Active current ProjectSettings companion only; full sample restoration remains pending',
                'Filesystem-to-audio and physical device integration still require validation'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(final_sha256=result['main_sha256'],remaining_services=result['sample_manager']['unresolved_services']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
