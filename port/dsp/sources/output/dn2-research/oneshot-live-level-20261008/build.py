"""Post-donor per-voice sample LEVEL with a bounded32-sample gain ramp."""
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
CODE_DM=0x2de980
CODE_SW=CODE_DM//2
STATE_DM=0x30de60
SAVE_DM=0x30dea0
HOOK=0x185d0a
RESUME=HOOK+3
REGS=[*[f'R{i}' for i in range(9)],'I4']
sha=lambda b:hashlib.sha256(b).hexdigest()

def source():
    s='''// LEVEL after donor output and before native DN2 AMP/filter processing.
// The port adds the independently isolated sample-level factor only: (raw/32768)^2.
// DN2 already supplies its common gain path; do not transplant DT2's common*2.
// Per-voice previous gain,32samples ramp, no record/phase/trigger writes.
.SECTION/PM seg_pmco;
.GLOBAL level_entry.;
level_entry.:
'''
    for i,r in enumerate(REGS):s+=f'      DM({SAVE_DM+4*i:#x}) = {r};\n'
    s+='''      // The proven output buffer is32floats. Reject other block sizes safely.
      R0 = DM(0x30dc34);
      R1 = 32;
      COMP(R0, R1);
      IF NE JUMP 0x0; // -> level_restore.
      R0 = DM(0x30dc94);
      R1 = 16;
      COMPU(R0, R1);
      IF GE JUMP 0x0; // -> level_restore.
      R3 = LSHIFT R0 BY 2;
      R1 = 0x30de60;
      R3 = R1 + R3;
      I4 = R3;
      R4 = DM(0, I4);
      // Corrupt/nonfinite retained gain becomes zero; finite gains stay bounded.
      R0 = LSHIFT R4 BY -23;
      R1 = 255;
      R0 = R0 AND R1;
      COMP(R0, R1);
      IF NE JUMP 0x0; // -> level_previous_finite.
      R4 = 0;
.GLOBAL level_previous_finite.;
level_previous_finite.:
      R0 = 0;
      F4 = MAX(F4, F0);
      R0 = 0x3f800000;
      F4 = MIN(F4, F0);
      // Parameter slot34 is byte18 from the voice's TUNE-slot base.
      R0 = DM(0x30dc9c);
      R1 = 18;
      R0 = R1 + R0;
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
      R0 = -15;
      F2 = FLOAT R2 BY R0;
      F2 = F2 * F2;
      R0 = 0x3f800000;
      F2 = MIN(F2, F0);
      // Retain exact target; native ramp starts from old gain and advances per point.
      I4 = R3;
      DM(0, I4) = R2;
      F5 = F2 - F4;
      R0 = 0x3d000000;
      F5 = F5 * F0;
      R7 = DM(0x30dca8);
      R6 = 32;
.GLOBAL level_sample.;
level_sample.:
      I4 = R7;
      R1 = DM(0, I4);
      F1 = F1 * F4;
      DM(0, I4) = R1;
      F4 = F4 + F5;
      R0 = 4;
      R7 = R0 + R7;
      R0 = 1;
      R6 = R6 - R0;
      IF NE JUMP 0x0; // -> level_sample.
.GLOBAL level_restore.;
level_restore.:
'''
    for i,r in reversed(list(enumerate(REGS))):s+=f'      {r} = DM({SAVE_DM+4*i:#x});\n'
    s+=f'      R0 = DM(0x30dcd8);\n      JUMP {RESUME:#x};\n'
    return s

def assemble():
    s=source();path=HERE/'level.asm';path.write_text(s)
    obj,offsets=m3._selas(path,HERE)
    symbols=O.symbols((HERE/'level.doj').read_bytes())
    labels={name:CODE_SW+offset for name,offset in symbols.items() if name.startswith('level_')}
    s=re.sub(r'((?:JUMP|CALL)\s+)0x[0-9a-f]+(;\s*// -> (level_\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],s)
    path.write_text(s);obj2,offsets2=m3._selas(path,HERE);assert offsets==offsets2
    return O.load_bytes(obj2),offsets,labels

def main():
    code,offsets,labels=assemble()
    assert CODE_DM+len(code)<=0x2def00
    baseline=(ROOT/'firmware/ghidra/storage-proof/bank-loader-v1/section_7.bin').read_bytes()
    assert sha(baseline)=='d831900f049b2bbc5a69b262660ee4c9908495ef3cb69ebad3a6244e82a8cd36'
    for at,n in ((CODE_DM,len(code)),(STATE_DM,104)):
        assert not any(p<0x28000000+at+n and 0x28000000+at<p+len(data) for p,data in B.load_regions(baseline))
    before=B.read_span(baseline,0x28000000+HOOK*2,6)
    expected,_=m3._selas_line('R0 = DM(0x30dcd8);',HERE)
    assert before==O.load_bytes(expected)
    patch,_=m3._selas_line(f'JUMP {CODE_SW:#x};',HERE);patch=O.load_bytes(patch);assert len(patch)==6
    (HERE/'level.bin').write_bytes(code)
    (HERE/'state-and-save-zero.bin').write_bytes(bytes(104))
    donor=ROOT/'output/dn2-research/oneshot-keyboard-dt2-20261008'
    proof=json.loads((donor/'level-native-verification.json').read_text())
    assert proof['ok'] and len(proof['cases'])==14 and len(proof['dn2_gain_cases'])==3
    assert proof['contract']['absolute_dt2_loudness_parity'] is False
    calibration={str((donor/name).relative_to(ROOT)):sha((donor/name).read_bytes()) for name in ('level-native-verification.json','level_native.py','level-static-proof.json')}
    report=dict(ok=True,code_dm=hex(CODE_DM),code_sw=hex(CODE_SW),bytes=len(code),end_exclusive=hex(CODE_DM+len(code)),sha256=sha(code),source_sha256=sha((HERE/'level.asm').read_bytes()),builder_sha256=sha(Path(__file__).read_bytes()),labels={k:hex(v) for k,v in labels.items()},instruction_offsets=offsets,state_dm=hex(STATE_DM),state_bytes=104,gain_bytes=64,saved_registers={r:hex(SAVE_DM+4*i) for i,r in enumerate(REGS)},hook=dict(sw=hex(HOOK),before=before.hex(),after=patch.hex(),resume=hex(RESUME)),record_writes=False,gain_calibration='Native sample factor only: min(1,(word/32768)^2); no duplicate native common gain*2.',calibration_review_pending=False,calibration_file_hashes=calibration,hardware_tested=False)
    (HERE/'build-receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('ok','code_dm','bytes','end_exclusive','sha256')},indent=2))
if __name__=='__main__':main()
