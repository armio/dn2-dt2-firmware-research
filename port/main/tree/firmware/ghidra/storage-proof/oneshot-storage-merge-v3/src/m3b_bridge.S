/* M3b bridge (2026-10-09): the SYN-page SAMP control's call into the
 * relocated DT2 donor name helper (0x47A53FA8), donor ABI shape:
 *   helper(this = a0 -> char* slot, [arg1 ignored], value @ sp+0x1C).
 * In:  d1 = raw SAMP value (the drawer's second argument).
 * Out: d0 = name char* (the helper's format writes it through a0).
 * Preserves d1-%d5/%a0-%a3 (the drawer keeps canvas/x/y/live state in them);
 * d0 was dead in the drawer at the call site. The value is sent through the
 * documented halved-transport adaptation (the stock mirror halves SAMP, so
 * the DSP slot = raw >> 1; the M3 doc's interim until the slot-28 frame
 * shim), and cached per changed value so the helper's native heap format
 * runs on changes only, never per frame. NAMESLOT/LASTVAL are baked in the
 * appended chain blob (zero / -1 at boot via the copier).
 */
.equ HELPER,   0x47A53FA8
.equ NAMESLOT, 0x47A540D4
.equ LASTVAL,  0x47A540D8
.text
.global m3b_bridge
m3b_bridge:
    lea     -32(%sp),%sp
    movem.l %d2-%d5/%a0-%a3,(%sp)
    move.l  %d1,%d2
    asr.l   #1,%d2               /* halved transport: DSP slot = raw >> 1 */
    cmp.l   LASTVAL,%d2
    beq.s   1f
    move.l  %d2,LASTVAL
    move.l  %d2,-(%sp)           /* value: the helper reads it at sp+0x1C */
    lea     NAMESLOT,%a0         /* this: the char* slot written through */
    move.l  %a0,-(%sp)           /* arg1: unused by the helper (donor passes the stack object) */
    jsr     HELPER
    addq.l  #8,%sp
1:  move.l  NAMESLOT,%d0
    movem.l (%sp),%d2-%d5/%a0-%a3
    lea     32(%sp),%sp
    rts