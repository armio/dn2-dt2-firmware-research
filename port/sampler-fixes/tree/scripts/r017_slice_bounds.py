"""Keep the SLICE frame producer inside the Sound's 64-row marker table."""
from build_dn2_sampler_fixes_r014 import BE

STEREO = 0x47a80100


def apply(ctx):
    native = int(ctx.doc['slice']['native_start'], 16)
    # A zero grid plays the whole sample. Use its native marker representation
    # for empty/corrupt counts without consulting any marker row. The native
    # packer takes START in D6, END in D1 and LOOP in D0.
    guard = ctx.append_asm('slice_select_bounds', f""".text
 move.l 316(%a0),%d7
 beq.s whole_sample
 cmpi.l #64,%d7
 bhi.s whole_sample
 mvz.b 96(%a5),%d0
 tst.l %d0
 bne.s select
 mvs.w %d6,%d6
 cmpi.l #0xc00,%d6
 bge.s select
 move.l #0xc00,%d6
select:
 jmp {native+8:#x}
whole_sample:
 moveq #0,%d6
 moveq #-1,%d1
 moveq #0,%d0
 jmp {native+0x86:#x}
""")
    ctx.replace(native, bytes.fromhex('712d00602e28013c'), b'\x4e\xf9' + BE(guard) + b'\x4e\x71')
    # LEN is an unsigned number of additional regions. Native code already
    # bounds the sum at the last row; a sign-extended corrupt byte bypassed it.
    ctx.replace(native + 0x4c, bytes.fromhex('7f2d0062'), bytes.fromhex('7fad0062'))
    # Use the SAMP value actually packed for this frame, including knob/trig
    # locks. The native waveform's size getter divides PCM bytes by two, then
    # halves the result for stereo. Sample replacement can leave a perfectly
    # ordered but obsolete grid in the Sound. Never feed a stale start or a
    # loop on the exclusive end to the reverse interpolator.
    sizes = int(ctx.doc['pool_model']['sizes'], 16)
    span = ctx.append_asm('slice_ordered_span', f""".text
 mvz.w 224(%a4),%d2
 cmpi.l #1023,%d2
 bhi.s fallback
 lea {sizes:#x},%a1
 move.l (%a1,%d2.l*4),%d3
 lsr.l #1,%d3
 lea {STEREO:#x},%a1
 tst.b (%a1,%d2.l)
 beq.s extent
 lsr.l #1,%d3
extent:
 cmp.l %d3,%d6
 bcc.s fallback
 cmpi.l #-1,%d1
 beq.s check_span
 cmp.l %d3,%d1
 bls.s check_span
 move.l %d3,%d1
check_span:
 cmp.l %d1,%d6
 bcs.s check_loop
fallback:
 moveq #0,%d6
 moveq #-1,%d1
 moveq #0,%d0
 bra.s pack
check_loop:
 cmp.l %d3,%d0
 bcc.s use_start
 cmp.l %d6,%d0
 bcs.s use_start
 cmp.l %d1,%d0
 bcs.s reverse_margin
use_start:
 move.l %d6,%d0
reverse_margin:
 mvz.b 220(%a4),%d2
 cmpi.l #1,%d2
 bne.s pack
 subi.l #141,%d3
 bcs.s fallback
 cmp.l %d3,%d0
 bls.s pack
 move.l %d3,%d0
 cmp.l %d3,%d6
 bls.s pack
 move.l %d3,%d6
pack:
 move.w %d6,240(%a4)
 move.w %d1,244(%a4)
 jmp {native+0x8e:#x}
""")
    ctx.replace(native + 0x86, bytes.fromhex('394600f0394100f4'),
                b'\x4e\xf9' + BE(span) + b'\x4e\x71')
    return dict(entry=hex(guard), span=hex(span), min_note=12, max_slices=64,
                slot_lengths=hex(sizes), stereo_flags=hex(STEREO),
                empty_grid_markers=[0, 0xffffffff, 0])
