"""Standalone active-record STRT/LEN/LOOP/PLAY refresh, inside pitch save scope."""
from pathlib import Path
import hashlib,json,re,sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
SRC=ROOT/'firmware/ghidra/oneshot-proof/v7-source'
sys.path[:0]=[str(SRC/'src'),str(SRC/'scripts')]
import sharc_waverider_render as m1
import sharc_waverider_m3 as m3
from dnfw.image import bootstream as B,sharc_object as O
m1.SELAS=str(ROOT/'firmware/ghidra/oneshot-proof/v6-source/toolchain/selache-2b26d3b/target/release/selas')
CODE_DM=0x2de700
CODE_SW=CODE_DM//2
sha=lambda b:hashlib.sha256(b).hexdigest()

def read_word(offset,dest,limit,coarse=False):
    text=f'''      R0 = {offset};
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
      R2 = R2 AND R1;
'''
    if coarse:text+='      R2 = LSHIFT R2 BY -8;\n'
    return text+f'      R1 = {limit};\n      R{dest} = MIN(R2, R1);\n'

def source():
    s='''// Refresh an existing active ONESHOT record without triggering or reseeding.
// CALL only after the outer pitch shim saved registers and existing ACTIVE guard.
// Reads native frame words: PLAY+2, STRT+12, LEN+14, LOOP+16.
// Preserves existing adapter minimum141 and integer scaling; no sample lookup.
// R0..R15/I4/flags may change. No stack data, persistent scratch, or M registers.
.SECTION/PM seg_pmco;
.GLOBAL live_controls_entry.;
live_controls_entry.:
      R15 = DM(0x30dc98);
      R0 = 0x188;
      R0 = R15 + R0;
      I4 = R0;
      R14 = DM(0, I4);
      R0 = 141;
      COMPU(R14, R0);
      IF LT JUMP 0x0; // -> live_controls_return.
      R0 = 32767;
      COMPU(R14, R0);
      IF GT JUMP 0x0; // -> live_controls_return.
      R13 = DM(0x30dc9c);
'''
    s+=read_word(2,7,3,True)
    s+=read_word(12,8,0x7800)
    s+=read_word(14,9,0x7800)
    s+=read_word(16,10,0x7800)
    s+='''      // Exact existing adapter arithmetic, using the current record length.
      R11 = 0;
      R0 = R8 * R14 (SSI);
      R0 = LSHIFT R0 BY -10;
      R2 = 2185;
      R0 = R0 * R2 (SSI);
      R0 = LSHIFT R0 BY -16;
      R1 = 141;
      R2 = R14 - R1;
      R0 = MIN(R0, R2);
      R4 = R9 * R14 (SSI);
      R4 = LSHIFT R4 BY -10;
      R2 = 2185;
      R4 = R4 * R2 (SSI);
      R4 = LSHIFT R4 BY -16;
      R4 = R0 + R4;
      R4 = MIN(R4, R14);
      R5 = R0 + R1;
      R4 = MAX(R4, R5);
      R1 = 1;
      R6 = R10 - R1;
      R6 = MAX(R6, R11);
      R6 = R6 * R14 (SSI);
      R6 = LSHIFT R6 BY -10;
      R2 = 2185;
      R6 = R6 * R2 (SSI);
      R6 = LSHIFT R6 BY -16;
      R2 = 141;
      R2 = R4 - R2;
      COMP(R6, R2);
      IF GT R6 = PASS R0;
      R10 = PASS R10;
      IF EQ R6 = PASS R0;
      // Decode donor PLAY order: REV, REV.L, FWD.L, FWD.
      R9 = LSHIFT R7 BY -1;
      R9 = R9 AND R1;
      R8 = R1 - R9;
      R10 = R7 AND R1;
      R9 = R9 XOR R10;
      // Bounds only. Phase, step, seed, active, stop and envelope state survive.
      R2 = 0x190;
      R2 = R15 + R2;
      I4 = R2;
      R2 = LSHIFT R6 BY 31;
      DM(0, I4) = R2;
      R2 = LSHIFT R6 BY -1;
      DM(1, I4) = R2;
      R2 = LSHIFT R0 BY 31;
      DM(2, I4) = R2;
      R2 = LSHIFT R0 BY -1;
      DM(3, I4) = R2;
      R2 = LSHIFT R4 BY 31;
      DM(4, I4) = R2;
      R2 = LSHIFT R4 BY -1;
      DM(5, I4) = R2;
      R2 = 0x1b8;
      R2 = R15 + R2;
      I4 = R2;
      R0 = DM(0, I4);
      R1 = 0x00ffffff;
      R0 = R0 AND R1;
      R8 = LSHIFT R8 BY 24;
      R0 = R0 OR R8;
      DM(0, I4) = R0;
      R0 = DM(1, I4);
      R1 = 0xffffff00;
      R0 = R0 AND R1;
      R0 = R0 OR R9;
      DM(1, I4) = R0;
.GLOBAL live_controls_return.;
live_controls_return.:
      RETURN;
'''
    return s

def assemble():
    s=source();path=HERE/'controls.asm';path.write_text(s)
    obj,offsets=m3._selas(path,HERE)
    symbols=O.symbols((HERE/'controls.doj').read_bytes())
    labels={name:CODE_SW+offset for name,offset in symbols.items() if name.startswith('live_controls_')}
    s=re.sub(r'((?:JUMP|CALL)\s+)0x[0-9a-f]+(;\s*// -> (live_controls_\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],s)
    path.write_text(s);obj2,offsets2=m3._selas(path,HERE);assert offsets==offsets2
    return O.load_bytes(obj2),offsets,labels

def main():
    code,offsets,labels=assemble()
    assert len(code)<=0x800
    baseline=(ROOT/'firmware/ghidra/storage-proof/bank-loader-v1/section_7.bin').read_bytes()
    assert sha(baseline)=='d831900f049b2bbc5a69b262660ee4c9908495ef3cb69ebad3a6244e82a8cd36'
    assert not any(at<0x28000000+CODE_DM+len(code) and 0x28000000+CODE_DM<at+len(data) for at,data in B.load_regions(baseline))
    (HERE/'controls.bin').write_bytes(code)
    report=dict(ok=True,code_dm=hex(CODE_DM),code_sw=hex(CODE_SW),bytes=len(code),end_exclusive=hex(CODE_DM+len(code)),sha256=sha(code),source_sha256=sha((HERE/'controls.asm').read_bytes()),builder_sha256=sha(Path(__file__).read_bytes()),labels={k:hex(v) for k,v in labels.items()},instruction_offsets=offsets,scratch_bytes=0,record_write_spans=[[0x190,0x1a8],[0x1b8,0x1c0]],preserved_flag_bytes=[0x1b8,0x1b9,0x1ba,0x1bd,0x1be,0x1bf],phase_written=False,step_written=False,abi='CALL after outer save-all and active guard. Clobbers R0..R15, I4 and flags; RETURN. Reads globals30DC98/30DC9C. No software-stack/frame or M changes.')
    (HERE/'build-receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('ok','code_dm','bytes','end_exclusive','sha256')},indent=2))

if __name__=='__main__':main()
