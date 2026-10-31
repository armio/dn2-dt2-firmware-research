#!/usr/bin/env python3
"""Connect original DT2 cache event cases to DN2 UI and background executor."""
from pathlib import Path
import argparse,json,struct,tempfile
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-waveform-cache-20261009'
SHA='6a96b3c90bf926a8b147126fbcefb6fce42466c6a6249afb0ac4c01d53c050ca'

# Explicit counterparts, not inferred from a caller. The factory and enqueue
# bodies, and each deque/std::function helper listed in TWINS, are checked
# independently below. Their 16-byte functions / 36-byte queue nodes match.
BINDINGS={0x40198a16:0x4018d0ea,0x400f0ab8:0x400f2494,
    0x40197a04:0x40188086,0x4011e8f0:0x40120264,0x4011e8fc:0x40120270,
    0x400f0c18:0x400f25f4,0x44f37090:0x44647930,0x44f37094:0x44647934,
    0x40197a4a:0x401880cc,0x401ecf4c:0x401d9184,
    0x401ba102:0x401a9caa,0x401cb736:0x401b40a2,0x401e7a64:0x401ce69e,
    0x44f37244:0x44647a74,0x401e723c:0x401cde76,0x4019b870:0x4018df5e,
    0x401cb768:0x401b40d4,0x401cb8d0:0x401b423c,0x401cb70e:0x401b407a,
    0x401e5fb4:0x401ccbee,0x4019e114:0x4018d036,0x4019e0ee:0x4018e55a,
    0x401cb89a:0x401b4206,0x4013a8a8:0x40138d54,0x401e4446:0x401cb080,
    0x43172e38:0x42c69224,0x43172de4:0x42c691d0,0x400f0774:0x400f2150,
    0x40215d88:0x401ff75c,0x40215d98:0x401ff76c,
    0x45672351:0x45672351,0x4002f178:0x4002f178,0x4002f196:0x4002f196,
    0x4002f19a:0x4002f19a}
TWINS=[(0x40198a16,0x40198ab2),(0x400f0ab8,0x400f0c16),
       (0x400f0c18,0x400f0c56),(0x401ba102,0x401ba134),
       (0x401cb736,0x401cb768),(0x4019b870,0x4019b89a),
       (0x401cb768,0x401cb7a2),(0x401cb8d0,0x401cba76),
       (0x401cb70e,0x401cb736),(0x40197a04,0x40197a20),
       (0x4019e0ee,0x4019e114),(0x4019e114,0x4019e134)]

def build(out):
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    doc=json.loads((INPUT/'build-receipt.json').read_text());evidence=[]
    for lo,hi in TWINS:
        new=BINDINGS[lo];blob=bytearray(donor[lo-B.BASE:hi-B.BASE])
        rows=list(B.M.S.disasm(donor,B.BASE,lo,hi))
        for operand,target,_,_ in B.M.operands(rows):
            struct.pack_into('>I',blob,operand-lo,BINDINGS.get(target,target))
        assert blob==native[new-B.BASE:new-B.BASE+len(blob)],hex(lo)
        evidence.append(dict(donor=hex(lo),native=hex(new),bytes=len(blob),
            kind='complete body equal after explicit absolute operand bindings'))
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='waveform_events';L.LIMIT=0x47a90000
    L.CODE=[('event_cases',0x400344a8,0x400345ce),('unload_tails',0x400349ca,0x400349ec),
            ('capture_manager',0x400330f2,0x4003314e),('load_job',0x40033774,0x400337ba)]
    L.DATA=[('capture_type',0x401f1010,0x401f1018)]
    L.EXTRA_STATE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_DATA={};L.STATE_ALIGNMENT=4
    L.EXTRA_SPANS=[];bindings={}
    # Later components carry corrected bindings (notably the exact default
    # waveform identity). They must take precedence over earlier adapters.
    for key in ('pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:bindings[int(e['target'],16)]=int(e['binding'],16)
    bindings.update(BINDINGS);L.EXTRA_BINDINGS=bindings
    L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    assembly=(B.T.ROOT/'scripts/asm/dn2_waveform_events.S').read_text()
    exit_assembly='''.text
 unlk %a6
 movem.l (%sp),%d0-%d7/%a0-%a6
 lea 60(%sp),%sp
 jmp 0x4002f178
 .balign 4
'''
    with tempfile.TemporaryDirectory(prefix='dn2-waveform-events-') as tmp:
        tmp=Path(tmp)
        dispatch=B.R.assemble(assembly,0x47f00000,tmp,'dispatch')
        exit_code=B.R.assemble(exit_assembly,0x40033d00,tmp,'exit')
    L.EXTRA_CODE=[('native_dispatch',0x47f00000,dispatch),('event_exit',0x40033d00,exit_code)]
    L.METHODS={'dispatch':0x47f00000,'exit':0x40033d00,'loaded':0x400344a8,
        'unloaded':0x4003450a,'job':0x40033774,'capture_manager':0x400330f2}
    L.build(out)
    image=bytearray((out/'main-os.bin').read_bytes());doc=json.loads((out/'build-receipt.json').read_text())
    hook=0x4002f190;assert image[hook-B.BASE:hook-B.BASE+6]==bytes.fromhex('303b0a0848c0')
    image[hook-B.BASE:hook-B.BASE+6]=b'\x4e\xf9'+B.BE(int(doc['waveform_events']['methods']['dispatch'],16))
    doc['main_sha256']=B.T.SHA(image)
    doc['waveform_events'].update(native_dispatch_hook=hex(hook),native_executor='0x4018d0ea',
        native_enqueue='0x400f2494',native_worker='0x400f2334',native_twins=evidence,
        limits=['UI and executor scheduling, physical waveform DMA and hardware behavior remain untested.'])
    (out/'main-os.bin').write_bytes(image)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    (out/'event-dispatch.S').write_text(assembly);(out/'event-exit.S').write_text(exit_assembly)
    print(json.dumps(dict(main_sha256=doc['main_sha256'],hook=hex(hook),methods=doc['waveform_events']['methods']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
