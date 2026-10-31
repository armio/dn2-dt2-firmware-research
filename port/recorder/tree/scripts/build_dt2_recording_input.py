#!/usr/bin/env python3
"""Connect DT2's original capture, trigger, meter and audition code to DN2 audio.

The bridge only adapts the native frame ABI and the DN2 source buffers. Capture,
threshold/transport trigger, length limiting, normalization and audition remain
DT2 instructions. No device I/O.
"""
from pathlib import Path
import argparse, json, re, struct
import build_dt2_preview_audio as P
import build_dt2_recording_rpc as Q
import build_dt2_dsp_startup_fix as L
C, R, A, O, V = P.C, P.N, P.A, P.O, P.V
BASE = C.ROOT/'output/dn2-research/dt2-dsp-usb-multitrack-tap-20261012/section_7.bin'
BASE_SHA = '409811b1776c9a2cf1c73e5fce2f5dbcf7378c9fd6f835f45ba1a0e97c1a3cc3'
CODE, BRIDGE, MONITOR, MON_BODY = 0xbf8000, 0xbf9000, 0xbf9800, 0xbf9900
MON_SITE, MON_RESUME = 0x1c3038, 0x1c303b
STATE, TABLE, SAVE, CTX = 0x200dc000, 0x200f8800, 0x200f8b00, 0x200f8d00
WIRE, WIRE_SAVE, WIRE_CODE = 0x200f8d40, 0x200f8d60, 0xbfa800
WIRE_SITE, WIRE_RESUME = 0x1c2883, 0x1c2886
SITE, RESUME, OLD = 0x1c3064, 0x1c3067, 0
SPANS = (('controls',0x1c33fe,0x1c35cd,CODE),
         ('capture',0x1c367e,0x1c39cf,CODE+0x200),
         ('float-predicates',0x1c0c0e,0x1c0c36,CODE+0x600),
         ('log10-entry',0x1c0c40,0x1c0c49,CODE+0x640),
         ('monitor-override',0x1c301d,0x1c3043,MON_BODY))
REGS = P.REGS
EXTERNAL = {0xb88e4e:0xbe8900,0x1c0c4b:0x1c0b6b}


def mapped(v, *, required=False):
    for _,lo,hi,to in SPANS:
        if lo<=v<hi:return to+v-lo
    if 0x256a44<=v<0x256a98:return STATE+v-0x256a44
    if 0x256a98<=v<0x256ca8:return TABLE+v-0x256a98
    if 0x2526f0<=v<0x252718:return v+0x538c
    if v in EXTERNAL:return EXTERNAL[v]
    if required:raise ValueError(f'Unbound recorder target {v:#x}')
    return v


def label(n): return f'.GLOBAL rec_{n}.;\nrec_{n}.:\n'
def jump(n, cond=''):return f'      {cond} JUMP 0x0; // -> rec_{n}.\n'
def call(addr,n):return V.linked(mapped(addr,required=True),f'rec_{n}.')

def source(wire):
    # Wire consists of native low/high 16-bit fields and native word-swapped
    # trim values. Last word is a bridge enable cookie, never a donor control.
    s='.SECTION/PM seg_pmco;\n'+label('entry')
    # Closed recorder costs only a cookie check, preserving the original flags.
    for i,reg in enumerate(('R0','R1','ASTATX')):s+=f'      DM({CTX+32+4*i:#x}) = {reg};\n'
    s+=f'''      R0 = DM({wire+24:#x});
      R0 = LSHIFT R0 BY -16;
      R1 = 0x5243;
      COMP(R0, R1);
'''+jump('enabled','IF EQ')
    for i,reg in enumerate(('R0','R1','ASTATX')):s+=f'      {reg} = DM({CTX+32+4*i:#x});\n'
    s+=jump('replay')+label('enabled')
    for i,reg in enumerate(('R0','R1','ASTATX')):s+=f'      {reg} = DM({CTX+32+4*i:#x});\n'
    for i,reg in enumerate(REGS):s+=f'      DM({SAVE+4*i:#x}) = {reg};\n'
    s+=f'''      R0 = DM({CTX:#x});
      R1 = 1;
      COMP(R0, R1);
'''+jump('initialized','IF EQ')+call(0x1c34b7,'init_done')+f'''      R0 = 1;
      DM({CTX:#x}) = R0;
      R0 = -1;
      DM({CTX+4:#x}) = R0;
      DM({CTX+8:#x}) = R0;
'''+label('initialized')
    # Cache length/tempo, leaving donor's exact 64-bit length calculation.
    s+=f'''      R0 = DM({wire:#x});
      R1 = 0xffff;
      R4 = R0 AND R1;
      R8 = DM(0x25c564);
      R8 = R8 AND R1;
      R0 = DM({CTX+4:#x});
      COMP(R0, R4);
'''+jump('length_update','IF NE')+f'''      R0 = DM({CTX+8:#x});
      COMP(R0, R8);
'''+jump('length_done','IF EQ')+label('length_update')+f'''      DM({CTX+4:#x}) = R4;
      DM({CTX+8:#x}) = R8;
'''+call(0x1c3570,'length_done')
    s+=f'      R4 = DM({wire:#x});\n      R4 = LSHIFT R4 BY -16;\n'+call(0x1c355c,'threshold_done')
    s+=f'      R4 = DM({wire+8:#x});\n      R4 = LSHIFT R4 BY -16;\n'+call(0x1c3493,'trigger_done')
    s+=f'      R4 = DM({wire+12:#x});\n      R4 = LSHIFT R4 BY -16;\n'+call(0x1c3486,'transport_done')
    s+=f'      R4 = DM({wire+24:#x});\n      R0 = 0xffff;\n      R4 = R4 AND R0;\n'+call(0x1c3416,'loop_done')
    for off,reg in [(16,'R4'),(20,'R8')]:
        s+=f'      R0 = DM({wire+off:#x});\n      R1 = LSHIFT R0 BY 16;\n      R0 = LSHIFT R0 BY -16;\n      {reg} = R0 OR R1;\n'
    s+=call(0x1c341e,'trim_done')
    s+=f'      R4 = DM({wire+12:#x});\n      R0 = 0xffff;\n      R4 = R4 AND R0;\n'+call(0x1c3504,'command_done')
    # Exact native source enum: MAIN0, USB1, TRACK1..16=2..17, physical INPUT18.
    s+=f'''      R0 = DM({wire+4:#x});
      R1 = 0xffff;
      R4 = R0 AND R1;
      R2 = LSHIFT R0 BY -16;
      DM({CTX+20:#x}) = R2;
      R1 = 0;
      COMP(R4, R1);
'''+jump('source_main','IF EQ')+'''      R1 = 1;
      COMP(R4, R1);
'''+jump('source_usb','IF EQ')+'''      R1 = 18;
      COMP(R4, R1);
'''+jump('source_input','IF EQ')+'''      R1 = 2;
      R4 = R4 - R1;
      R1 = 0;
      R4 = MAX(R4, R1);
      R1 = 15;
      R4 = MIN(R4, R1);
      R0 = LSHIFT R4 BY 8;
      R1 = 0x258f68;
      R0 = R0 + R1;
      R1 = 128;
      R1 = R0 + R1;
'''+jump('source_channels')+label('source_main')+'''      R0 = DM(-25, I6);
      R1 = 128;
      R1 = R0 + R1;
'''+jump('source_channels')+label('source_usb')+'''      R0 = DM(0x25be68);
      R1 = DM(0x25be6c);
'''+jump('source_channels')+label('source_input')+'''      I4 = DM(-31, I6);
      R0 = DM(0, I4);
      R1 = DM(1, I4);
'''+label('source_channels')+f'''      R2 = DM({CTX+20:#x});
      R3 = 1;
      COMP(R2, R3);
      IF EQ R1 = R0;
      R3 = 2;
      COMP(R2, R3);
      IF EQ R0 = R1;
      DM({CTX+12:#x}) = R0;
      DM({CTX+16:#x}) = R1;
      R4 = {CTX+12:#x};
'''+call(0x1c3429,'source_bound')
    s+=f'''      R8 = DM({CTX+20:#x});
      R4 = DM(-25, I6);
'''+call(0x1c367e,'rendered')
    # Existing native CF accessors consume these exact original DT2 offsets.
    for old,off in [(0x1c340e,4),(0x1c3406,8)]:
        s+=call(old,'read_'+str(off))+f'''      R1 = LSHIFT R0 BY 16;
      R0 = LSHIFT R0 BY -16;
      R0 = R0 OR R1;
      I4 = DM(1, I6);
      DM({off//4}, I4) = R0;
'''
    for old,off in [(0x1c398f,12),(0x1c39af,14),(0x1c399f,16),(0x1c39bf,18),(0x1c33fe,20)]:
        s+=call(old,'read_'+str(off))+f'''      I4 = DM(1, I6);
      R1 = DM({off//4}, I4);
      R2 = {0xffff0000 if off%4==0 else 0xffff:#x};
      R1 = R1 AND R2;
'''
        if off%4:s+='      R0 = LSHIFT R0 BY 16;\n'
        s+=f'      R0 = R0 OR R1;\n      DM({off//4}, I4) = R0;\n'
    s+=label('restore')
    order=[*(f'{bank}{i}' for bank in ('R','S','B','L','I','M') for i in range(16)), 'ASTATX','ASTATY','MODE1']
    for reg in order:s+=f'      {reg} = DM({SAVE+4*REGS.index(reg):#x});\n'
    s+=label('replay')+f'      I0 = 0x12345678;\n      JUMP {RESUME:#x};\n'
    return s


def monitor_source(wire):
    s='.SECTION/PM seg_pmco;\n'+label('monitor_entry')
    for i,reg in enumerate(('R0','R1','I4','ASTATX')):s+=f'      DM({CTX+48+4*i:#x}) = {reg};\n'
    s+=f"""      R0 = DM({wire+24:#x});
      R0 = LSHIFT R0 BY -16;
      R1 = 0x5243;
      COMP(R0, R1);
"""+jump('monitor_restore','IF NE')+f"""      R0 = DM({wire+4:#x});
      R1 = 0xffff;
      R0 = R0 AND R1;
      R1 = 18;
      COMP(R0, R1);
"""+jump('monitor_restore','IF NE')+f"""      R0 = DM({wire+8:#x});
      R1 = 0xffff;
      R0 = R0 AND R1;
      R1 = 0;
      COMP(R0, R1);
"""+jump('monitor_restore','IF EQ')+f'      JUMP {MON_BODY:#x};\n'+label('monitor_restore')
    for i,reg in enumerate(('R0','R1','I4','ASTATX')):s+=f'      {reg} = DM({CTX+48+4*i:#x});\n'
    s+=label('monitor_replay')+'      I0 = 0x12345678;\n'+f'      JUMP {MON_RESUME:#x};\n'
    return s


def build(out,wire):
    assert wire==WIRE, 'Recorder controls must use private L2 state, not native voice owners.'
    raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
    donorraw=C.DONOR.read_bytes();assert C.SHA(donorraw)==C.DONOR_SHA
    doc=json.loads((BASE.parent/'build-receipt.json').read_text())
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    n=L.decode_view(k,raw);d=k.ldr.LoadedMemory.from_stream(donorraw)
    out.mkdir(parents=True,exist_ok=False);blocks=[];spans=[]
    for name,lo,hi,to in SPANS:
        body,bindings,listing=R.relocate(k,d,lo,hi,to,mapper=mapped)
        blocks.append((C.S.code_address(to,window='l2'),body))
        (out/(name+'.asm')).write_text('\n'.join(listing)+'\n')
        spans.append(dict(name=name,donor=hex(lo),end=hex(hi),target=hex(to),bytes=len(body),bindings=bindings))
    table=bytearray(d.read(C.S.data_address(0x256a98),0x210))
    for i in range(4):struct.pack_into('<I',table,0x200+4*i,mapped(struct.unpack_from('<I',table,0x200+4*i)[0],required=True))
    blocks.extend([(TABLE,bytes(table)),(SAVE,bytes(0x200)),(CTX,bytes(0x40)),(WIRE,bytes(28)),(WIRE_SAVE,bytes(4))])
    # Native SPI receives 0xABC bytes into each 4KB page; CF controls occupy
    # existing padding at +A80..+A9B. I4 already points there after the native
    # 672-word snapshot. Never extend that snapshot: its tail holds voice owners.
    ws='.SECTION/PM seg_pmco;\n'+f'      DM({WIRE_SAVE:#x}) = I0;\n'
    for off in range(0,28,4):ws+=f'      I0 = DM({off//4}, I4);\n      DM({WIRE+off:#x}) = I0;\n'
    ws+=f'      I0 = DM({WIRE_SAVE:#x});\n      I4 = 0x25d6c4;\n      JUMP {WIRE_RESUME:#x};\n'
    wa=out/'wire-snapshot.asm';wa.write_text(ws);wb,wo=A._selas(wa,out);wirebody=O.load_bytes(wb)
    wire_before=n.read_sw(WIRE_SITE,6)
    assert wire_before==C.S.to_bytes(0x0f140025d6c4),wire_before.hex()
    blocks.append((C.S.code_address(WIRE_CODE,window='l2'),wirebody))
    s=source(wire);asm=out/'recording-bridge.asm';asm.write_text(s);be,offsets=A._selas(asm,out)
    labels={n:BRIDGE+v for n,v in O.symbols((out/'recording-bridge.doj').read_bytes()).items() if n.startswith('rec_')}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (rec_\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],s)
    s=re.sub(r'(DM\(I7, M7\) = )0x0(; // return: (rec_\w+\.))',lambda m:m[1]+hex(labels[m[3]]-1)+m[2],s)
    asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
    body=bytearray(O.load_bytes(be));fixes=[]
    for off in offsets:
        if off+6>len(body):continue
        v=C.S.to_value(body[off:off+6]);reg=(v>>32)&0x7f
        if v>>40 in (0x10,0x11) and reg in (0x70,0x73,0x74):
            body[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(BRIDGE+off//2))
    assert len(fixes)==9
    before=n.read_sw(SITE,6);assert before.hex()=='3e6c2810e082',before.hex()
    at=2*(labels['rec_replay.']-BRIDGE);assert C.S.to_value(body[at:at+6])==0x0f1012345678,hex(C.S.to_value(body[at:at+6]))
    body[at:at+6]=before
    blocks.append((C.S.code_address(BRIDGE,window='l2'),bytes(body)))
    ms=monitor_source(wire);ma=out/'monitor-bridge.asm';ma.write_text(ms);mb,mo=A._selas(ma,out)
    ml={n:MONITOR+v for n,v in O.symbols((out/'monitor-bridge.doj').read_bytes()).items() if n.startswith('rec_')}
    ms=re.sub(r'(JUMP\s+)0x0(;\s*// -> (rec_\w+\.))',lambda m:m[1]+hex(ml[m[3]])+m[2],ms)
    ma.write_text(ms);mb,again=A._selas(ma,out);assert again==mo
    monitor=bytearray(O.load_bytes(mb))
    for off in mo:
        if off+6<=len(monitor):
            v=C.S.to_value(monitor[off:off+6]);reg=(v>>32)&0x7f
            if v>>40 in (0x10,0x11) and reg==0x73:monitor[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|(0x76<<32))
    mon_before=n.read_sw(MON_SITE,6);assert mon_before==C.S.to_bytes(0x0f0c00257e6c),mon_before.hex()
    at=2*(ml['rec_monitor_replay.']-MONITOR);monitor[at:at+6]=mon_before
    blocks.append((C.S.code_address(MONITOR,window='l2'),bytes(monitor)))
    for i,(at,data) in enumerate(blocks):
        if at==C.S.code_address(MON_BODY,window='l2'):blocks[i]=(at,data+C.S.to_bytes(0x063e00000000|ml['rec_monitor_restore.']))
    placed=[]
    for at,b in blocks:
        assert 0x200f0000<=at<at+len(b)<=0x200fa000,hex(at)
        assert not any(a<at+len(b) and at<a+len(v) for a,v in (*C.B.load_regions(raw),*placed)),hex(at)
        placed.append((at,b))
    image=bytearray(raw);C.B.write_span(image,C.S.code_address(SITE),C.S.to_bytes(0x063e00000000|BRIDGE))
    C.B.write_span(image,C.S.code_address(MON_SITE),C.S.to_bytes(0x063e00000000|MONITOR))
    C.B.write_span(image,C.S.code_address(WIRE_SITE),C.S.to_bytes(0x063e00000000|WIRE_CODE))
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False,recording_input_connected=True)
    doc['recording_input']=dict(spans=spans,hook=dict(site=hex(SITE),resume=hex(RESUME),before=before.hex()),bridge=hex(BRIDGE),bridge_bytes=len(body),labels={k:hex(v) for k,v in labels.items()},instruction_offsets=offsets,system_register_fixes=fixes,wire=hex(wire),state=hex(STATE),tables=hex(TABLE),save=hex(SAVE),context=hex(CTX),recording_buffer=dict(start=hex(Q.RECORD),frames_per_channel=Q.CAPACITY,bytes=Q.RECORD_BYTES,end=hex(Q.R.POOL)),contract='DT2 capture, threshold/transport trigger, length, meters and recording audition. Native recording readback/normalization RPCs retain same state and float arena.',limits=['Not yet tested on physical hardware.'])
    doc['recording_input']['source_enum']={'0':'MAIN','1':'USB','2..17':'TRACK1..16','18':'physical INPUT'}
    doc['recording_input']['track_source']=hex(0x258f68)
    doc['recording_input']['wire_snapshot']=dict(site=hex(WIRE_SITE),resume=hex(WIRE_RESUME),code=hex(WIRE_CODE),bytes=len(wirebody),instruction_offsets=wo,scratch=hex(WIRE_SAVE),wire_offset='0xa80',control_bytes=28,native_rx_bytes=0xabc,rx_buffers=['0x2c29d0','0x2c39d0'],contract='Copy existing SPI padding into private L2; preserve native 0xA80 snapshot, all sixteen voice owners at +A5A..+A79, USB flags and adjacent globals. No transfer size change.')
    doc['recording_input']['track_source_contract']='Native1C1F9C..1C1FEC maps16voice planes257EE8 through owner table257898 into per-track sums258F68 before capture. Includes all allocated voices and native mute fades.'
    doc['recording_input']['monitor']=dict(site=hex(MON_SITE),resume=hex(MON_RESUME),bridge=hex(MONITOR),body=hex(MON_BODY),bytes=len(monitor),instruction_offsets=mo,labels={k:hex(v) for k,v in ml.items()},donor_fields=['0x2526f0','0x252714'],native_fields=['0x257a7c','0x257aa0'],semantics='Exact donor PRE MIX override for physical input: unity levels, centered pans, zero sends. POST MIX leaves native external-mixer settings. Runs before native mixer and USB export.')
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),bridge_bytes=len(body),wire=hex(wire))))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--wire',type=lambda s:int(s,0),required=True);a=p.parse_args();build(a.out,a.wire)
