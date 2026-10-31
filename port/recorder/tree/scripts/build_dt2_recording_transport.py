#!/usr/bin/env python3
"""Carry the DT2 recorder controls and transport-start event in DN2 frames."""
from pathlib import Path
import argparse,json,struct,tempfile
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-recording-settings-20261015'
SHA='5abdf01a768aa039d306732c7fe91e114f883656a244adc8e858a539b84f4ed2'
LIMIT=0x47ad0000
COMMAND,CONTROL,ENTRY=0x402a1490,0x47f30200,0x47f31000
PACKET=0x47f30220
FRAME_HOOK,EVENT_HOOK,TAIL_HOOK=0x4002765a,0x40026304,0x400cf93c
NATIVE={0x47f32000:0x40027660,0x47f32004:0x40026e50,
        0x47f32008:0x4002630c,0x47f3200c:0x42431aad,
        0x47f32010:0x400cf942}
FIELDS=(('length',0),('threshold',2),('source',4),('channels',6),('monitor',8),('trigger',10),
        ('command',12),('transport_start',14),('trim_start',16),('trim_end',20),('audition_mode',24))


def assembly(settings):
    cfg=settings['fields']
    def old(name):return 0x429369c8+cfg[name]['offset']
    s=f'''.text
.global recorder_frame_hook,recorder_frame,recorder_transport_event,recorder_open,recorder_close,recorder_spi_tail
recorder_frame_hook:
 move.l %d1,-(%sp)
 bsr.w recorder_frame
 move.l (%sp)+,%d1
 move.l 0x47f3200c,%d0
 jmp 0x47f32000
recorder_frame:
 tst.w {CONTROL:#x}
 beq.w recorder_disabled
 move.w {CONTROL+2:#x},%d0
 cmpi.w #1,%d0
 bne.s recorder_check_ack
 moveq #2,%d0
 move.w %d0,{CONTROL+2:#x}
 bra.s recorder_fields
recorder_check_ack:
 cmpi.w #2,%d0
 bne.s recorder_fields
 move.w 0x80001a34,%d0
 cmpi.w #2,%d0
 bne.s recorder_fields
 clr.w {CONTROL:#x}
 clr.w {CONTROL+2:#x}
 bra.w recorder_disabled
recorder_fields:
'''
    for name,offset in FIELDS[:6]:
        s+=f' move.w {old(name)+2:#x},%d0\n move.w %d0,{PACKET+offset:#x}\n'
    s+=f''' move.w {COMMAND+2:#x},%d0
 move.w %d0,{PACKET+12:#x}
 move.w {CONTROL+4:#x},%d0
 move.w %d0,{PACKET+14:#x}
'''
    # Preserve the exact donor high/low halfword packing, including sign
    # extension before the high-half store used by its transport encoder.
    for name,offset in [('trim_start',16),('trim_end',20)]:
        s+=f''' move.l {old(name):#x},%d0
 move.l %d0,%d1
 swap %d1
 ext.l %d1
 move.w %d0,{PACKET+offset+2:#x}
 move.w %d1,{PACKET+offset:#x}
'''
    s+=f''' move.w {old('audition_mode')+2:#x},%d0
 move.w %d0,{PACKET+24:#x}
 move.l #0x5243,%d0
 move.w %d0,{PACKET+26:#x}
 clr.w {CONTROL+4:#x}
 rts
recorder_disabled:
 clr.w {PACKET+26:#x}
 clr.w {CONTROL+4:#x}
 rts
/* Native event kind7 is DT2's transport-start pulse. DN2 otherwise ignores it. */
recorder_transport_event:
 moveq #7,%d5
 cmp.l %d0,%d5
 bne.s recorder_other_event
 moveq #1,%d5
 move.w %d5,{CONTROL+4:#x}
 moveq #7,%d5
 jmp 0x47f32004
recorder_other_event:
 jmp 0x47f32008
recorder_open:
 moveq #2,%d0
 move.l %d0,{COMMAND:#x}
 clr.w {CONTROL+2:#x}
 clr.w {CONTROL+4:#x}
 move.l #0x5243,%d0
 move.w %d0,{CONTROL:#x}
 rts
recorder_close:
 moveq #2,%d0
 move.l %d0,{COMMAND:#x}
 tst.w {CONTROL:#x}
 beq.s recorder_closed
 moveq #1,%d0
 move.w %d0,{CONTROL+2:#x}
recorder_closed:
 rts
/* Normal audio already clocks ABC bytes. Fill fourteen of its thirty padding
   words instead of touching the native A80-byte voice/control frame. */
recorder_spi_tail:
 cmpa.l #0xa80,%a2
 bne.w recorder_spi_original
 cmpa.l #0x800068e0,%a3
 bne.w recorder_spi_original
 cmpi.l #0x54e,%d1
 blt.w recorder_spi_original
 lea -8(%sp),%sp
 movem.l %d2/%a0,(%sp)
 lea {PACKET:#x},%a0
 move.l #0x540,%d2
recorder_spi_words:
 move.w (%a0)+,2(%a1,%d2.l*4)
 addq.l #1,%d2
 cmpi.l #0x54e,%d2
 blt.s recorder_spi_words
 movem.l (%sp),%d2/%a0
 lea 8(%sp),%sp
recorder_spi_original:
 subq.l #1,%d1
 move.w (%a1,%d1.l*4),%d0
 jmp 0x47f32010
.balign 4
'''
    return s


def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text());cfg=doc['recording_settings']
    native=B.M.RECIPIENT.read_bytes();donor=B.M.S.DONOR.read_bytes()
    raw=(INPUT/'main-os.bin').read_bytes()
    assert raw[FRAME_HOOK-B.BASE:FRAME_HOOK-B.BASE+6]==native[FRAME_HOOK-B.BASE:FRAME_HOOK-B.BASE+6]==bytes.fromhex('203942431aad')
    assert raw[EVENT_HOOK-B.BASE:EVENT_HOOK-B.BASE+8]==native[EVENT_HOOK-B.BASE:EVENT_HOOK-B.BASE+8]==bytes.fromhex('7a07ba8067000b46')
    assert raw[TAIL_HOOK-B.BASE:TAIL_HOOK-B.BASE+6]==native[TAIL_HOOK-B.BASE:TAIL_HOOK-B.BASE+6]==bytes.fromhex('538130311c00')
    assert native[0x40027d3a-B.BASE:0x40027d42-B.BASE]==bytes.fromhex('203c00000abc4e75')
    assert donor[0x4002e14a-B.BASE:0x4002e152-B.BASE]==bytes.fromhex('7207b28067000564')
    assert donor[0x4002e6b4-B.BASE:0x4002e6ba-B.BASE]==bytes.fromhex('72011d41ff93')
    assert native[0x400cfa74-B.BASE:0x400cfa7c-B.BASE]==bytes.fromhex('303980001a344e75')
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='recording_transport';L.LIMIT=LIMIT
    L.CODE=[('native_command_setter',0x4002f47a,0x4002f486)];L.DATA=[]
    L.EXTRA_DATA={};L.EXTRA_TYPED_DATA=[]
    L.EXTRA_STATE=[('recording_command',COMMAND,COMMAND+4),('recording_control',CONTROL,CONTROL+8),
                   ('recording_packet',PACKET,PACKET+28)]
    L.STATE_ALIGNMENT=4;L.EXTRA_SPANS=[];bindings={}
    for comp in doc.values():
        if not isinstance(comp,dict):continue
        for edit in comp.get('edits',[]):
            if 'target' in edit and 'binding' in edit:bindings[int(edit['target'],16)]=int(edit['binding'],16)
        if isinstance(comp.get('spans'),list):
            L.EXTRA_SPANS[0:0]=[s for s in comp['spans'] if all(k in s for k in ('donor','end','runtime'))]
    for field in cfg['fields'].values():
        old=0x429369c8+field['offset'];at=int(field['address'],16)
        bindings[old]=at;bindings[old+2]=at+2
    # Native continuation PCs can overlap already relocated donor ranges.
    # Distinct synthetic symbols prevent those ranges taking precedence.
    bindings.update(NATIVE)
    src=assembly(cfg)
    with tempfile.TemporaryDirectory(prefix='recording-transport-') as temp:
        temp=Path(temp);code=B.R.assemble(src,ENTRY,temp,'recording-transport')
        symbols={parts[2]:int(parts[0],16) for line in B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',temp/'recording-transport.elf']).splitlines() if len(parts:=line.split())==3 and parts[2].startswith('recorder_')}
    L.EXTRA_CODE=[('frame_control_adapter',ENTRY,code)]
    L.EXTRA_BINDINGS=bindings;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'set_command':0x4002f47a,**symbols,'open':symbols['recorder_open'],'close':symbols['recorder_close']}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());cfg=doc['recording_transport']
    image=bytearray((out/'main-os.bin').read_bytes());payload=bytearray((out/'runtime.bin').read_bytes())
    copy=doc['runtime_copy'];base=int(copy['destination'],16);source=int(copy['source'],16)-B.BASE
    state=next(int(s['runtime'],16) for s in cfg['spans'] if s['name']=='recording_control')
    cmd=next(int(s['runtime'],16) for s in cfg['spans'] if s['name']=='recording_command')
    packet=next(int(s['runtime'],16) for s in cfg['spans'] if s['name']=='recording_packet')
    payload[cmd-base:cmd-base+4]=B.BE(2)
    image[source:source+len(payload)]=payload
    patches=[]
    for site,name,length in [(FRAME_HOOK,'recorder_frame_hook',6),(EVENT_HOOK,'recorder_transport_event',8),
                             (TAIL_HOOK,'recorder_spi_tail',6)]:
        entry=int(cfg['methods'][name],16);before=bytes(image[site-B.BASE:site-B.BASE+length])
        after=b'\x4e\xf9'+B.BE(entry)+b'\x4e\x71'*((length-6)//2)
        image[site-B.BASE:site-B.BASE+length]=after
        patches.append(dict(site=hex(site),before=before.hex(),after=after.hex(),entry=hex(entry)))
    cfg.update(patches=patches,command_address=hex(cmd),command_word=hex(cmd+2),
        enabled=hex(state),close_pending=hex(state+2),transport_start_pending=hex(state+4),
        packet_base=hex(packet),packet_bytes=28,enable_word=hex(packet+26),enable_cookie='0x5243',
        wire_offset='0xa80',wire_end='0xa9c',dsp_snapshot='0x200f8d40',
        native_frame=dict(base='0x80005e60',bytes=0xa80,unchanged=True,
                          voice_owner_range=['0xa5a','0xa7a'],usb_post_offset='0xa7a'),
        padding_transport=dict(native_rx_clock_bytes=0xabc,source='0x40027d3a -> 0x400cf688 -> 0x42440958',
            hook='0x400cf93c',guards=['TX length A80','advanced source 800068E0','clock extent >=A9C'],
            dma_buffer='0x80002510',tail_command_start='0x80003a10',tail_command_end='0x80003a48',
            existing_command_end='0x80003a88',control_word='0x8001',data_halfword_offset=2,
            protocol='Existing 30 padding words; first14 carry recorder28B, remaining16 follow native padding.'),
        source_choices={'0':'MAIN','1':'USB',**{str(i+2):f'TRACK {i+1}' for i in range(16)},'18':'PHYSICAL IN'},
        field_order=[dict(name=name,offset=offset,width=4 if name in ('trim_start','trim_end') else 2) for name,offset in FIELDS],
        transport_start_evidence={'donor_event_type':7,'donor_branch':'0x4002e14e','donor_pulse':'0x4002e6b4',
                                  'native_preexisting_ignored_event':'0x40026304..0x4002630c','behavior':'One pulse in the next control frame; cleared after frame fill even while recorder disabled.'},
        shutdown='Close requests command2, emits at least one enabled stop frame, then clears cookie only when native reply state at80001A34 equals2.',
        disabled_cost='Frame hook tests enable and clears two words; event hook preserves existing event7 branch behavior while recording one private pulse.',
        native_replay='Frame hook preserves D1, replays original MOVE.L42431AAD,D0 and resumes40027660; D5/event comparison preserved at event hook.',
        flash_ready=False)
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'recording-transport.S').write_text(src)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],command=hex(cmd),enabled=hex(state),methods=cfg['methods']),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--input',type=Path,default=INPUT);ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args();INPUT=args.input;SHA=B.T.SHA((INPUT/'main-os.bin').read_bytes());build(args.out)
