#!/usr/bin/env python3
"""Bind native DT2 recorder settings methods to private DN2 session state.

Original getters, clamps and ProjectSettings notifications remain intact.
Only their virtual raw-project reads use an adapter: recorder fields must
never occupy unverified offsets in the native DN2 project structure.
"""
from pathlib import Path
import argparse, json, struct, tempfile
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-recording-save-20261015'
SHA='4b54f18a0db7cd508637bb7dfc670f97694453ae30738434eca435613f57278b'
LIMIT=0x47ad0000
LO,HI=0x4004cc42,0x4004d11a
STATE,ACCESSOR=0x47f30000,0x47f30100
FIELDS={'source':0, 'threshold':4, 'monitor':8, 'length':12,
        'channels':16, 'trigger':20, 'trim_start':24, 'trim_end':28,
        'audition_mode':32}
ENTRIES={'get_length':0x4004cc42,'get_source':0x4004cc72,
         'get_channels':0x4004cca2,'get_threshold':0x4004ccd2,
         'get_monitor':0x4004cd02,'monitor_physical':0x4004cd32,
         'set_trigger':0x4004cd80,'get_trigger':0x4004cdd6,
         'get_trim_start':0x4004ce06,'set_trim_start':0x4004ce36,
         'get_trim_end':0x4004ce7e,'set_trim_end':0x4004ceae,
         'get_audition_mode':0x4004cef6,'set_audition_mode':0x4004cf26,
         'set_length':0x4004cf7c,'set_source':0x4004cfd6,
         'set_channels':0x4004d030,'set_threshold':0x4004d08a,
         'set_monitor':0x4004d0d2,'raw_settings':ACCESSOR}


def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='recording_settings';L.LIMIT=LIMIT
    L.CODE=[('project_recording_methods',LO,HI)];L.DATA=[]
    L.EXTRA_DATA={};L.EXTRA_TYPED_DATA=[];L.EXTRA_STATE=[('session_settings',STATE,STATE+36)]
    L.STATE_ALIGNMENT=4;L.EXTRA_SPANS=[];bindings={}
    for cfg in doc.values():
        if not isinstance(cfg,dict):continue
        for edit in cfg.get('edits',[]):
            if 'target' in edit and 'binding' in edit:
                bindings[int(edit['target'],16)]=int(edit['binding'],16)
        if isinstance(cfg.get('spans'),list):
            L.EXTRA_SPANS[0:0]=[s for s in cfg['spans'] if all(k in s for k in ('donor','end','runtime'))]
    source=f'''.text
 move.l 4(%sp),%a0
 move.l (%a0),%a0
 move.l 40(%a0),%a0
 move.l 4(%sp),-(%sp)
 jsr (%a0)
 addq.l #4,%sp
 tst.l %d0
 beq.s unavailable
 move.l #{STATE:#x},%d0
 subi.l #0x1ae,%d0
unavailable:
 rts
 .balign 4
'''
    with tempfile.TemporaryDirectory(prefix='recording-settings-') as temp:
        L.EXTRA_CODE=[('raw_settings',ACCESSOR,B.R.assemble(source,ACCESSOR,Path(temp),'settings-raw'))]
    L.EXTRA_BINDINGS=bindings;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True
    L.INFER_NATIVE_LIBRARY_OPERANDS=False;L.METHODS=ENTRIES
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());cfg=doc['recording_settings']
    copy=doc['runtime_copy'];base=int(copy['destination'],16);src=int(copy['source'],16)-B.BASE
    code_at=next(int(s['runtime'],16) for s in cfg['spans'] if s['name']=='project_recording_methods')
    state=next(int(s['runtime'],16) for s in cfg['spans'] if s['name']=='session_settings')
    raw_getter=int(cfg['methods']['raw_settings'],16)
    payload=bytearray((out/'runtime.bin').read_bytes());image=bytearray((out/'main-os.bin').read_bytes())
    donor=B.M.S.DONOR.read_bytes();rows=list(B.M.S.disasm(donor,B.BASE,LO,HI));patches=[]
    for pc,hx,mn,ops in rows:
        if hx!='20680028':continue
        assert donor[pc-B.BASE:pc-B.BASE+6]==bytes.fromhex('206800284e90')
        at=code_at+pc-LO
        assert payload[at-base:at-base+6]==bytes.fromhex('206800284e90')
        payload[at-base:at-base+6]=b'\x4e\xb9'+B.BE(raw_getter)
        patches.append(dict(donor=hex(pc),runtime=hex(at),before='206800284e90',after=(b'\x4e\xb9'+B.BE(raw_getter)).hex()))
    assert len(patches)==39,len(patches)
    defaults=[18,0,0,8,0,0,0,0,0]
    payload[state-base:state-base+36]=struct.pack('>9I',*defaults)
    image[src:src+len(payload)]=payload
    cfg.update(raw_access_patches=patches,settings_address=hex(state),raw_bias=hex(state-0x1ae),
        fields={name:dict(offset=offset,address=hex(state+offset),width=4,default=defaults[offset//4]) for name,offset in FIELDS.items()},
        donor_settings_raw_base='0x4293681a',
        frame_mapping={name:dict(donor=hex(0x4293681a+0x1ae+offset+(2 if offset<24 or offset==32 else 0)),
                                address=hex(state+offset+(2 if offset<24 or offset==32 else 0)),
                                width=2 if offset<24 or offset==32 else 4) for name,offset in FIELDS.items()},
        persistence='Session-only recorder preferences; initialized once at boot. Native project payload and existing sample-identity persistence remain unchanged.',
        validation='Exact donor setters clamp source0..18,length0..8,channels0..3,trigger/audition0..1; threshold,monitor,trim setters preserve native unrestricted values.',
        notifications='Original ProjectSettings vtable+0x10 notification with argument0, after each accepted setter.',
        native_project_fields_written=False,flash_ready=False)
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],settings=hex(state),raw_bias=cfg['raw_bias'],methods=cfg['methods']),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--input',type=Path,default=INPUT);ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args();INPUT=args.input;SHA=B.T.SHA((INPUT/'main-os.bin').read_bytes());build(args.out)
