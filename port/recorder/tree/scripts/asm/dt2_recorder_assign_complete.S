.text
.global recorder_assign_complete
/* Original completion is UI-thread code. Convert a synth only after a
 * successful pool load; preserve the full donor status/assignment dialog. */
recorder_assign_complete:
 move.l %a2,-(%sp)
 move.l %d2,-(%sp)
 tst.l 16(%sp)
 bne.s complete
 movea.l 12(%sp),%a0
 movea.l (%a0),%a0
 move.l 4(%a0),%d2
 cmpi.l #15,%d2
 bhi.s complete
 jsr 0x401988a2
 move.l %d0,-(%sp)
 jsr 0x40041d24
 addq.l #4,%sp
 movea.l %d0,%a2
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x40035cca
 addq.l #8,%sp
 move.l %d0,-(%sp)
 jsr 0x46030004
 addq.l #4,%sp
 cmpi.l #4,%d0
 bhi.s complete
 pea 1
 pea 1
 pea 5
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x46030000
 lea 20(%sp),%sp
complete:
 move.l (%sp)+,%d2
 movea.l (%sp)+,%a2
 jmp 0x4001922e
.balign 4
