"""DSP-only extract from build_dt2_werp_live.py; MAIN never imported."""
import build_dt2_sampler_dispatch as D
ORIGINAL_DSP_SOURCE = D.source

def dsp_source():
    source = ORIGINAL_DSP_SOURCE()
    # This is the sampler-private note event. The native engine's note and
    # envelope trigger cells are never modified for a WERP segment transition.
    before = '''native_lifecycle_done.:
      R2 = DM(0x30dce0);'''
    after = f'''native_lifecycle_done.:
      R0 = DM({D.CURRENT:#x});
      R1 = 6;
      COMP(R0, R1);
      IF NE JUMP 0x0; // -> native_segment_done.
      R0 = DM(0x30dc9c);
      R1 = 36;
      R0 = R0 + R1;
      R1 = 0xfffffffc;
      R2 = R0 AND R1;
      I4 = R2;
      R2 = DM(0, I4);
      R1 = 2;
      R0 = R0 AND R1;
      R0 = LSHIFT R0 BY 3;
      R0 = -R0;
      R2 = LSHIFT R2 BY R0;
      R1 = 0xffff;
      R2 = R2 AND R1;
      R2 = PASS R2;
      IF EQ JUMP 0x0; // -> native_segment_done.
      R0 = 1;
      DM(0x30dce8) = R0;
.GLOBAL native_segment_done.;
native_segment_done.:
      R2 = DM(0x30dce0);'''
    assert source.count(before) == 1
    source = source.replace(before, after)
    before = f'''      R1 = {D.WARP:#x};
      R0 = R1 + R0;
      I4 = R0;
      R0 = DM(0, I4);
      DM({D.F.CTX+20:#x}) = R0;'''
    after = D.F.read_word(32)+'''      R12 = LSHIFT R8 BY 16;
'''+D.F.read_word(34)+f'''      R0 = R12 OR R8;
      DM({D.F.CTX+20:#x}) = R0;'''
    assert source.count(before) == 1
    return source.replace(before, after)

def build(out):
    old = D.source
    D.source = dsp_source
    try:
        D.build(out)
    finally:
        D.source = old
