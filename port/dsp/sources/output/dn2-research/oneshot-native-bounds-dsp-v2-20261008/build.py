"""Native DT2 normalized bounds and seed tail, with DN2 frame/input adapters."""
from pathlib import Path
import hashlib,json,re,struct,sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
SRC=ROOT/'firmware/ghidra/oneshot-proof/v7-source'
sys.path[:0]=[str(SRC/'src'),str(SRC/'scripts')]
import sharc_waverider_render as m1
import sharc_waverider_m3 as m3
from dnfw.image import bootstream as B,sharc_object as O
m1.SELAS=str(ROOT/'firmware/ghidra/oneshot-proof/v6-source/toolchain/selache-2b26d3b/target/release/selas')
BASE=ROOT/'output/dn2-research/oneshot-keyboard-dsp-v2-20261008/section_7.bin'
BASE_SHA='77a8cd4bace91b5a0bfc243713cd2b5e5da7881912fbe06a3b54c60a963a2c08'
DONOR=ROOT/'firmware/dt2-1.16/section_7_blob.bin'
DONOR_DIR=ROOT/'output/dn2-research/oneshot-native-bounds-dt2-20261008'
BOUNDS_DM=0x2deb00;BOUNDS_SW=BOUNDS_DM//2
CONVERT_DM=0x2dee00;CONVERT_SW=CONVERT_DM//2
SEED_DM=0x2def00;SEED_SW=SEED_DM//2
CODE_DM=0x2df000;CODE_SW=CODE_DM//2
HOOK=0x16f380
sha=lambda b:hashlib.sha256(b).hexdigest()

def assemble_text(name,source,sw):
    path=HERE/(name+'.asm');path.write_text(source)
    be,offsets=m3._selas(path,HERE)
    syms=O.symbols((HERE/(name+'.doj')).read_bytes())
    labels={k:sw+v for k,v in syms.items() if k.startswith('native_')}
    source=re.sub(r'((?:JUMP|CALL)\s+)0x[0-9a-f]+(;\s*// -> (native_\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],source)
    source=re.sub(r'(DM\(I7, M7\) = )0x[0-9a-f]+(;\s*// return: (native_\w+\.))',lambda m:m[1]+hex(labels[m[3]]-1)+m[2],source)
    path.write_text(source);be2,offsets2=m3._selas(path,HERE)
    assert offsets==offsets2
    return O.load_bytes(be2),offsets,labels

def donor_components():
    dk=m1.Digikit(SRC/'toolchains/digikit')
    memory=dk.ldr.LoadedMemory.from_stream(DONOR.read_bytes())
    old=0x1c4914;original=memory.read_sw(old,(0x1c4a27-old)*2)
    code=bytearray(original);relocs=[]
    def operand(pc,before,after,kind):
        off=(pc-old)*2+2
        assert code[off:off+4]==struct.pack('<HH',before>>16,before&0xffff)
        code[off:off+4]=struct.pack('<HH',after>>16,after&0xffff)
        relocs.append(dict(sw=hex(pc),offset=off,before=hex(before),after=hex(after),kind=kind))
    operand(0x1c4949,0xb88f70,CONVERT_SW,'native signed64-to-float import')
    for pc in (0x1c496b,0x1c498b,0x1c49a2):operand(pc,0xb88f06,0x187ec0,'existing native float-to-signed64 import')
    for pc,ret in ((0x1c494d,0x1c494f),(0x1c4971,0x1c4973),(0x1c498f,0x1c4991),(0x1c49a6,0x1c49a8)):
        operand(pc,ret,BOUNDS_SW+ret-old,'linked return address')
    # This assertion is unreachable after the input guard. A defensive branch
    # uses the original restoration epilogue instead of importing an OS assert.
    operand(0x1c4944,0xe3,0x1c49c9-0x1c4944,'invalid short-length branch to native restore/return')
    helper=(DONOR_DIR/'int64-to-float-native.bin').read_bytes()
    assert helper==memory.read_sw(0xb88f70,244)
    tail=memory.read_sw(0x1c4bad,110)
    ret,_=m3._selas_line('RETURN;',HERE)
    seed=tail+O.load_bytes(ret)
    for name,data in [('bounds-original.bin',original),('bounds.bin',bytes(code)),('int64-to-float.bin',helper),('seed-original.bin',tail),('seed.bin',seed)]:
        (HERE/name).write_bytes(data)
    return bytes(code),helper,seed,relocs

def read_word(offset,dest):
    return f'''      R0 = {offset};
      R0 = R13 + R0;
      R1 = 0xfffffffc;
      R1 = R0 AND R1;
      I4 = R1;
      R2 = DM(0, I4);
      R1 = 2;
      R0 = R0 AND R1;
      R0 = LSHIFT R0 BY 3;
      R1 = 0;
      R0 = R1 - R0;
      R2 = LSHIFT R2 BY R0;
      R1 = 0xffff;
      R{dest} = R2 AND R1;
'''

def source():
    s='''// DN2 frame access and ABI bridge. All arithmetic bounds/seed decisions
// execute the relocated DT2 native functions. Called inside saved pitch scope.
.SECTION/PM seg_pmco;
.GLOBAL native_controls_entry.;
native_controls_entry.:
      R15 = DM(0x30dc98);
      I5 = R15;
      R0 = 0x188;
      R0 = R15 + R0;
      I4 = R0;
      R14 = DM(0, I4);
      R0 = DM(1, I4);
      R0 = PASS R0;
      IF NE JUMP 0x0; // -> native_controls_return.
      R0 = 141;
      COMPU(R14, R0);
      IF LT JUMP 0x0; // -> native_controls_return.
      R0 = 32767;
      COMPU(R14, R0);
      IF GT JUMP 0x0; // -> native_controls_return.
      R13 = DM(0x30dc9c);
'''
    s+=read_word(2,7)+read_word(12,8)+read_word(14,9)+read_word(16,10)
    s+='''      // Native parameter maxima; LOOP has its own OFF-plus-range endpoint.
      R0 = 0x7800;
      R8 = MIN(R8, R0);
      R9 = MIN(R9, R0);
      R0 = 0x7802;
      R10 = MIN(R10, R0);
      R7 = LSHIFT R7 BY -8;
      R0 = 3;
      R7 = MIN(R7, R0);
      // DT2 PLAY order: REV, REV.L, FWD.L, FWD.
      R1 = 1;
      R2 = LSHIFT R7 BY -1;
      R2 = R2 AND R1;
      R3 = R7 AND R1;
      R3 = R3 XOR R2;
      R2 = R1 - R2;
      R2 = LSHIFT R2 BY 24;
      R0 = 0x1b8;
      R0 = R15 + R0;
      I4 = R0;
      R4 = DM(0, I4);
      R0 = 0x00ffffff;
      R4 = R4 AND R0;
      R4 = R4 OR R2;
      // Nonzero native ON reached the existing complete seed path before
      // this guarded hook. Mark SEED so native phase replaces provisional phase.
      R0 = DM(0x30dce8);
      R0 = PASS R0;
      IF EQ JUMP 0x0; // -> native_no_trigger.
      R0 = 0x00010000;
      R4 = R4 OR R0;
.GLOBAL native_no_trigger.;
native_no_trigger.:
      DM(0, I4) = R4;
      R4 = DM(1, I4);
      R0 = 0xffffff00;
      R4 = R4 AND R0;
      R4 = R4 OR R3;
      DM(1, I4) = R4;
      // Native DT2 unpack units for all three raw unsigned16 frame words.
      R0 = 0x38088889;
      F8 = FLOAT R8;
      F9 = FLOAT R9;
      F10 = FLOAT R10;
      F12 = F8 * F0;
      F9 = F9 * F0;
      F2 = F10 * F0;
      DM(I7, M7) = R9; // normalized LEN, second stack argument
      // Exact native compensated LOOP conversion operations, register-adapted.
      R1 = 0x463b8400;
      R0 = 0x3f800000;
      R11 = 0x38aec33e;
      R14 = 0x463b8000;
      F2 = F2 * F1;
      F6 = F2 - F0;
      F1 = F6 * F11;
      F0 = MANT F1;
      F2 = F1 * F14;
      IF NOT AV F2 = F2 - F6;
      F2 = F2 * F11;
      IF NOT AV F1 = F1 - F2;
      DM(I7, M7) = R1; // normalized LOOP, first stack argument
      R4 = I5;
      R8 = PASS R3;
      CJUMP 0x16f580 (DB);
      DM(I7, M7) = R2;
      DM(I7, M7) = 0x0; // return: native_bounds_return.
.GLOBAL native_bounds_return.;
native_bounds_return.:
      R0 = I7;
      R1 = 8;
      R0 = R1 + R0;
      I7 = R0;
      // Native phase tail reads byte SEED at I3+14 and REVERSE at record+1BB.
      R0 = I5;
      R1 = 0x1ac;
      R0 = R1 + R0;
      I3 = R0;
      CALL 0x16f780;
.GLOBAL native_controls_return.;
native_controls_return.:
      RETURN;
'''
    return s

def main():
    base=BASE.read_bytes();assert sha(base)==BASE_SHA
    bounds,convert,seed,relocs=donor_components()
    code,offsets,labels=assemble_text('bridge',source(),CODE_SW)
    assert CODE_DM+len(code)<=0x2df600
    placements=[('native DT2 normalized bounds',BOUNDS_DM,bounds),('native int64-to-float',CONVERT_DM,convert),('native seed and phase tail',SEED_DM,seed),('DN2 input bridge',CODE_DM,code)]
    for name,at,data in placements:
        assert not any(a<0x28000000+at+len(data) and 0x28000000+at<a+len(b) for a,b in B.load_regions(base)),name
    out=bytearray(base)
    before=B.read_span(base,0x28000000+HOOK*2,6)
    expected,_=m3._selas_line('R15 = DM(0x30dc98);',HERE)
    assert before==O.load_bytes(expected)
    jump,_=m3._selas_line(f'JUMP {CODE_SW:#x};',HERE)
    patch=O.load_bytes(jump);assert len(patch)==6
    B.write_span(out,0x28000000+HOOK*2,patch)
    out=B.insert_before_final(bytes(out),b''.join(B.block(0x28000000+at,data) for _,at,data in placements))
    assert B.walk(out).complete
    (HERE/'section_7.bin').write_bytes(out);(HERE/'bridge.bin').write_bytes(code)
    report=dict(schema='dn2-oneshot-native-bounds-v1',baseline_sha256=sha(base),section7_sha256=sha(out),bytes=len(out),donor_sha256=sha(DONOR.read_bytes()),builder_sha256=sha(Path(__file__).read_bytes()),source_sha256=sha((HERE/'bridge.asm').read_bytes()),hook=dict(sw=hex(HOOK),before=before.hex(),after=patch.hex()),placements=[dict(name=n,address=hex(a),bytes=len(d),sha256=sha(d)) for n,a,d in placements],native_bounds_relocations=relocs,labels={k:hex(v) for k,v in labels.items()},instruction_offsets=offsets)
    (HERE/'build-receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
