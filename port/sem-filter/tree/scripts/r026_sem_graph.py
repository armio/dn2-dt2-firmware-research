"""R026: draw the SEM kernel's small-signal response in the FILTER graph cell (docs/DN2-R026-SEM-GRAPH-SPEC.md).

Retargets R023's `jsr sem_graph` (inside its dispatch) to `sem_curve`, which runs R023's drawing for the frame
and caption, clears the curve area and draws 48 segments computed exactly as sem_graph_reference.model does.
Only instruction forms native MAIN already uses (no ff1, no EMAC, no FPU); one divu.w per draw.
"""
import hashlib
import re
import struct
import subprocess

import build_dt2_sampler_runtime as native
import sem_graph_reference as R

HOOK_SITE = 0x47acf1aa          # jsr sem_graph inside R023 sem_graph_dispatch (runtime copy)
R023_GRAPH = 0x47acf1ba
FILL, LINE = 0x40114842, 0x40114148
FRAME = 356                     # saved registers + locals; arguments start at FRAME+4


def words(values):
    return '\n'.join(' .short ' + ','.join(map(str, values[i:i+16])) for i in range(0, len(values), 16))


def source(tb):
    return f'''.text
.global sem_curve
/* Wrapper: same arguments as R023 sem_graph (bitmap, FREQ raw, RESO raw, TYPE). */
sem_curve:
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 jsr {R023_GRAPH:#x}
 lea 16(%sp),%sp
 /* 0..39 saved, 40 wl, 44 wh, 48 1/Q^2, 52 cutoff, 56 band-pass, 60 rows (49 words), 160 offsets (49 longs). */
 lea -{FRAME}(%sp),%sp
 movem.l %d2-%d7/%a2-%a5,(%sp)
 clr.l -(%sp)
 pea 22
 pea 70
 pea 8
 pea 22
 move.l {FRAME+24}(%sp),-(%sp)
 jsr {FILL:#x}
 lea 24(%sp),%sp
 /* Output weights from TYPE: 2m = TYPE*4161/1024 rounded; TYPE 127 is band-pass. */
 move.l {FRAME+16}(%sp),%d0
 andi.l #127,%d0
 clr.l 40(%sp)
 clr.l 44(%sp)
 moveq #0,%d6
 cmpi.l #127,%d0
 bne.s curve_morph
 moveq #1,%d6
 bra.s curve_weights_done
curve_morph:
 move.l #4161,%d1
 muls.l %d1,%d0
 addi.l #512,%d0
 moveq #10,%d1
 asr.l %d1,%d0
 move.l %d0,%d1
 cmpi.l #256,%d1
 ble.s curve_wh
 move.l #256,%d1
curve_wh:
 move.l %d1,44(%sp)
 move.l #512,%d1
 sub.l %d0,%d1
 cmpi.l #256,%d1
 ble.s curve_wl
 move.l #256,%d1
curve_wl:
 move.l %d1,40(%sp)
curve_weights_done:
 move.l %d6,56(%sp)
 /* Q = 0.5 + 9.5*RESO/127 in Q8; 1/Q in Q12 by one divu.w; 1/Q^2 in Q18. */
 move.l {FRAME+12}(%sp),%d0
 andi.l #32767,%d0
 cmpi.l #32512,%d0
 ble.s curve_reso
 move.l #32512,%d0
curve_reso:
 move.l #4902,%d1
 muls.l %d1,%d0
 clr.w %d0
 swap %d0
 addi.l #128,%d0
 move.l #0x100000,%d1
 divu.w %d0,%d1
 andi.l #0xffff,%d1
 muls.l %d1,%d1
 asr.l #6,%d1
 move.l %d1,48(%sp)
 /* Cutoff: LT interpolated at fine FREQ, Q8 octaves. */
 move.l {FRAME+8}(%sp),%d0
 andi.l #32767,%d0
 move.l %d0,%d1
 lsr.l #8,%d1
 andi.l #255,%d0
 lea curve_lt,%a0
 mvs.w (%a0,%d1.l*2),%d2
 mvs.w 2(%a0,%d1.l*2),%d3
 sub.l %d2,%d3
 muls.l %d0,%d3
 asr.l #8,%d3
 add.l %d2,%d3
 move.l %d3,52(%sp)
 /* Columns 22..70. */
 lea curve_lx,%a2
 lea 60(%sp),%a3
 lea 160(%sp),%a4
 moveq #48,%d7
curve_column:
 mvs.w (%a2)+,%d3
 sub.l 52(%sp),%d3
 move.l %d3,(%a4)+
 cmpi.l #{R.CLAMP},%d3
 ble.s curve_clamp_low
 move.l #{R.CLAMP},%d3
curve_clamp_low:
 cmpi.l #-{R.CLAMP},%d3
 bge.s curve_clamped
 move.l #-{R.CLAMP},%d3
curve_clamped:
 move.l %d3,%d0
 bsr.w curve_exp2
 move.l %d0,%d4
 move.l %d3,%d0
 neg.l %d0
 bsr.w curve_exp2
 move.l %d0,%d5
 tst.l 56(%sp)
 bne.s curve_column_bp
 move.l 40(%sp),%d0
 muls.l %d5,%d0
 move.l 44(%sp),%d1
 muls.l %d4,%d1
 sub.l %d1,%d0
 asr.l #8,%d0
 muls.l %d0,%d0
 bra.s curve_column_den
curve_column_bp:
 move.l #0x40000,%d0
curve_column_den:
 sub.l %d5,%d4
 muls.l %d4,%d4
 add.l 48(%sp),%d4
 bsr.w curve_row
 move.w %d0,(%a3)+
 subq.l #1,%d7
 bpl.w curve_column
 /* Peak: the column with the smallest |offset| is evaluated at the cutoff (w = 1). */
 lea 160(%sp),%a4
 moveq #0,%d6
 move.l (%a4),%d5
 tst.l %d5
 bpl.s curve_peak_abs0
 neg.l %d5
curve_peak_abs0:
 moveq #1,%d7
curve_peak_scan:
 move.l (%a4,%d7.l*4),%d0
 tst.l %d0
 bpl.s curve_peak_abs
 neg.l %d0
curve_peak_abs:
 cmp.l %d5,%d0
 bge.s curve_peak_next
 move.l %d0,%d5
 move.l %d7,%d6
curve_peak_next:
 addq.l #1,%d7
 cmpi.l #49,%d7
 blt.s curve_peak_scan
 tst.l 56(%sp)
 bne.s curve_peak_bp
 move.l 40(%sp),%d0
 sub.l 44(%sp),%d0
 add.l %d0,%d0
 muls.l %d0,%d0
 bra.s curve_peak_row
curve_peak_bp:
 move.l #0x40000,%d0
curve_peak_row:
 move.l 48(%sp),%d4
 bsr.w curve_row
 lea 60(%sp),%a3
 move.w %d0,(%a3,%d6.l*2)
 /* Notch: zero at (log2 wl - log2 wh)/2 octaves, drawn on the floor when inside the columns. */
 move.l 40(%sp),%d0
 beq.w curve_draw
 tst.l 44(%sp)
 beq.w curve_draw
 bsr.w curve_log2
 move.l %d0,%d3
 move.l 44(%sp),%d0
 bsr.w curve_log2
 sub.l %d0,%d3
 asr.l #1,%d3
 lea 160(%sp),%a4
 cmp.l (%a4),%d3
 blt.w curve_draw
 cmp.l 192(%a4),%d3
 bgt.w curve_draw
 moveq #0,%d6
 move.l (%a4),%d5
 sub.l %d3,%d5
 bpl.s curve_notch_abs0
 neg.l %d5
curve_notch_abs0:
 moveq #1,%d7
curve_notch_scan:
 move.l (%a4,%d7.l*4),%d0
 sub.l %d3,%d0
 bpl.s curve_notch_abs
 neg.l %d0
curve_notch_abs:
 cmp.l %d5,%d0
 bge.s curve_notch_next
 move.l %d0,%d5
 move.l %d7,%d6
curve_notch_next:
 addq.l #1,%d7
 cmpi.l #49,%d7
 blt.s curve_notch_scan
 lea 60(%sp),%a3
 moveq #{R.FLOOR},%d0
 move.w %d0,(%a3,%d6.l*2)
curve_draw:
 /* 48 native line calls: (bitmap, x, 63-row[x], x+1, 63-row[x+1], 1). */
 lea 60(%sp),%a3
 moveq #22,%d7
curve_segment:
 pea 1
 mvs.w 2(%a3),%d1
 moveq #63,%d0
 sub.l %d1,%d0
 move.l %d0,-(%sp)
 move.l %d7,%d0
 addq.l #1,%d0
 move.l %d0,-(%sp)
 mvs.w (%a3),%d1
 moveq #63,%d0
 sub.l %d1,%d0
 move.l %d0,-(%sp)
 move.l %d7,-(%sp)
 move.l {FRAME+24}(%sp),-(%sp)
 jsr {LINE:#x}
 lea 24(%sp),%sp
 addq.l #2,%a3
 addq.l #1,%d7
 cmpi.l #70,%d7
 blt.s curve_segment
 movem.l (%sp),%d2-%d7/%a2-%a5
 lea {FRAME}(%sp),%sp
 rts
/* d0 = d (|d| <= CLAMP, Q8 octaves) -> d0 = 2^(d/256) in Q9. Clobbers d1, a0. */
curve_exp2:
 move.l %d0,%d1
 andi.l #255,%d1
 lsr.l #2,%d1
 lea curve_e,%a0
 mvz.w (%a0,%d1.l*2),%d1
 asr.l #8,%d0
 subq.l #6,%d0
 bge.s curve_exp2_left
 neg.l %d0
 lsr.l %d0,%d1
 move.l %d1,%d0
 rts
curve_exp2_left:
 lsl.l %d0,%d1
 move.l %d1,%d0
 rts
/* d0 = v (0 < v < 2^31) -> d0 = log2(v) in Q8. Clobbers d1, d2, a0. */
curve_log2:
 move.l %d0,%d2
 moveq #0,%d1
 cmpi.l #0xffff,%d2
 bls.s curve_log2_8
 clr.w %d2
 swap %d2
 addi.l #16,%d1
curve_log2_8:
 cmpi.l #0xff,%d2
 bls.s curve_log2_4
 lsr.l #8,%d2
 addq.l #8,%d1
curve_log2_4:
 cmpi.l #15,%d2
 bls.s curve_log2_2
 lsr.l #4,%d2
 addq.l #4,%d1
curve_log2_2:
 cmpi.l #3,%d2
 bls.s curve_log2_1
 lsr.l #2,%d2
 addq.l #2,%d1
curve_log2_1:
 cmpi.l #1,%d2
 bls.s curve_log2_mantissa
 addq.l #1,%d1
curve_log2_mantissa:
 move.l %d1,%d2
 subq.l #5,%d2
 blt.s curve_log2_small
 lsr.l %d2,%d0
 bra.s curve_log2_index
curve_log2_small:
 neg.l %d2
 lsl.l %d2,%d0
curve_log2_index:
 moveq #31,%d2
 and.l %d2,%d0
 lea curve_logm,%a0
 mvz.b (%a0,%d0.l),%d0
 lsl.l #8,%d1
 add.l %d1,%d0
 rts
/* d0 = num, d4 = den -> d0 = row (41..55). Clobbers d1, d2, d4, d5, a0. */
curve_row:
 tst.l %d0
 bne.s curve_row_level
 moveq #{R.FLOOR},%d0
 rts
curve_row_level:
 bsr.w curve_log2
 move.l %d0,%d5
 move.l %d4,%d0
 bsr.w curve_log2
 sub.l %d0,%d5
 addi.l #128,%d5
 asr.l #8,%d5
 moveq #{R.PASSBAND},%d0
 sub.l %d5,%d0
 moveq #{R.TOP},%d1
 cmp.l %d1,%d0
 bge.s curve_row_top
 move.l %d1,%d0
curve_row_top:
 moveq #{R.FLOOR},%d1
 cmp.l %d1,%d0
 ble.s curve_row_done
 move.l %d1,%d0
curve_row_done:
 rts
.balign 2
curve_lt:
{words(tb['LT'])}
curve_lx:
{words(tb['LX'])}
curve_e:
{words(tb['E'])}
curve_logm:
 .byte {','.join(map(str, tb['LOGM']))}
.balign 4
'''


def apply(ctx):
    g = R.cutoff_table()
    tb = R.tables(g)
    old = b'\x4e\xb9' + struct.pack('>I', R023_GRAPH)
    entry = ctx.append_asm('sem_curve', source(tb))
    symbols = {m[2]: int(m[1], 16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$', subprocess.check_output(
            [str(native.T.BIN/'binutils/nm-new'), '-n', str(ctx.work/'sem_curve.elf')], text=True))}
    if symbols['sem_curve'] != entry:
        raise ValueError('sem_curve entry is not the helper start')
    ctx.replace(HOOK_SITE, old, b'\x4e\xb9' + struct.pack('>I', entry))
    return dict(entry=hex(entry), methods={k: hex(v) for k, v in symbols.items()},
                hook_site=hex(HOOK_SITE), replaced_call=hex(R023_GRAPH),
                dsp_sha256=R.DSP_SHA, cutoff_table_sha256=R.TABLE_SHA,
                tables_sha256=hashlib.sha256(R.table_bytes(tb)).hexdigest(),
                scale='row = 48 - log2|H|^2 (3.01 dB per pixel), rows 41..55, columns 22..70',
                limits=['Small-signal response: the kernel soft clipping is not drawn.',
                        'Stored FREQ, RESO and TYPE only; no envelope, LFO or keytracking movement.',
                        "R023's schematic code and level table remain in the image, unused."])
