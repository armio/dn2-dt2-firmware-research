/* M3b drawer text region (2026-10-09): replaces the donor code-text calls
 * (slot==0 -> "OFF" / slot!=0 -> "%d" slot digits) in the relocated
 * 288-byte SAMP control at 0x47A53AE2. The bridge (jsr below) resolves the
 * DT2-donor name for the current SAMP value; the name is drawn through the
 * same native text call (a3 = 0x40115668) with the donor call-1 argument
 * shape: (canvas, font ''@0x402941D0, x = a2+12, y = d3, 1, 0, "XXX"@0x402170BA,
 * <text>). The name holds no '%' verbs, so it is its own format string, and
 * the bank-letter call (%c at a2+1) is skipped by the caller's patch.
 * Assembled at exactly 0x47A53B3C; 78 bytes total (36 bytes of nops pad).
 */
.equ M3B_BRIDGE, 0x47A5408C
.text
.global m3b_drawer_text
m3b_drawer_text:
    jsr     M3B_BRIDGE
    move.l  %d0,-(%sp)           /* name char* as the text argument */
    pea     0x402170ba            /* "XXX" style, as the donor calls */
    clr.l   -(%sp)
    pea     1
    move.l  %d3,-(%sp)            /* y */
    lea     %a2@(12),%a0
    move.l  %a0,-(%sp)            /* x */
    pea     0x402941d0             /* font '' */
    move.l  %d2,-(%sp)            /* canvas */
    jsr     (%a3)
    lea     0x20(%sp),%sp         /* pop the 8 pushed arguments */
    .rept 18
    nop
    .endr