.text
.align 2
.global os_controls_init, os_controls_sample, os_controls_loop, os_controls_sample_format
/* No workspace and no heap operations. Return 0 not ready, 1 ready, 3 changed.
 * Retain every std::function capture/manager and every editing field.
 * BSS only: 68-byte GUI table, never the separate 60-byte ROM value table.
 */
os_controls_init:
    lea -16(%sp),%sp
    movem.l %d2-%d3/%a2-%a3,(%sp)
    lea os_controls_rows,%a2
    moveq #6,%d3
    moveq #0,%d2
1:  move.l (%a2),%a0
    move.l 28(%a0),%d0
    cmpi.l #0x400bdc1a,%d0
    bne 5f
    move.l 32(%a0),%d0
    cmpi.l #0x400c0822,%d0
    beq 2f
    cmp.l 8(%a2),%d0
    bne 5f
2:  move.l (%a0),%d0
    beq 3f
    cmp.l 4(%a2),%d0
    bne 5f
3:  lea 12(%a2),%a2
    subq.l #1,%d3
    bpl 1b
    lea os_controls_rows,%a2
    moveq #6,%d3
    moveq #1,%d2
4:  move.l (%a2),%a0
    move.l 4(%a2),%d0
    cmp.l (%a0),%d0
    beq 6f
    move.l %d0,(%a0)
    moveq #3,%d2
6:  move.l 8(%a2),%d0
    cmp.l 32(%a0),%d0
    beq 7f
    move.l %d0,32(%a0)
    moveq #3,%d2
7:  lea 12(%a2),%a2
    subq.l #1,%d3
    bpl 4b
5:  move.l %d2,%d0
    movem.l (%sp),%d2-%d3/%a2-%a3
    lea 16(%sp),%sp
    rts
.align 2
os_controls_rows:
    .long 0x424332a0,0x20,0x400bd30a
    .long 0x424332e4,0x20,0x400bc50c
    .long 0x4243336c,0x24,os_controls_sample
    .long 0x424333b0,0x40,0x400bbfee
    .long 0x42433548,0x40,0x400bbfee
    .long 0x4243358c,0x40,os_controls_loop
    .long 0x424335d0,0x20,0x400c08fc
.align 2
os_controls_sample:
    .incbin "sample.bin"
.align 2
os_controls_loop:
    .incbin "loop.bin"
.align 2
/* The source native LOOP callback delegates nonzero values through this
 * immutable closure. Its first argument is unused by the existing drawer.
 * These objects are never registered with the stock allocator/destructor.
 */
os_controls_loop_delegate:
    .long 0,0,1,0x400bbfee
os_controls_unreachable:
    rts
/* The current proof bank has one physical sample. Its internal index0 is
 * visible as A1, not DT2 OFF. This formatter changes only the value overlay.
 * Native formatter ABI is (int value, char *destination), cdecl.
 */
os_controls_sample_format:
    movea.l 8(%sp),%a0
    move.w #0x4131,(%a0)
    clr.b 2(%a0)
    rts
