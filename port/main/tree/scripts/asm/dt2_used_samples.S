.text
.global used_sample_from_sound,used_sample_from_kit,used_sample_lock
/* Keep the donor scan and adapt only native object/data access. */
used_sample_from_sound:
 move.l 4(%sp),%a0
 move.l (%a0),%a1
 move.l %a0,-(%sp)
 move.l 40(%a1),%a0
 jsr (%a0)
 addq.l #4,%sp
 bra.s used_sample_raw

/* (Project*, kit index, track index) -> valid sample slot or -1. */
used_sample_from_kit:
 move.l %d2,-(%sp)
 move.l 16(%sp),%d2
 move.l 8(%sp),%a0
 move.l 12(%sp),-(%sp)
 lea 244(%a0),%a0
 move.l %a0,-(%sp)
 jsr 0x4019172e
 addq.l #8,%sp
 tst.l %d0
 beq.s used_sample_kit_done
 move.l %d0,%a0
 move.l #1163,%d0
 mulu.l %d2,%d0
 lea 52(%a0,%d0.l),%a0
 move.l %a0,%d0
used_sample_kit_done:
 move.l (%sp)+,%d2
used_sample_raw:
 tst.l %d0
 beq.s used_sample_absent
 move.l %d0,%a0
 mvz.b 222(%a0),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.w used_sample_absent
 mvs.w 76(%a0),%d0
 cmpi.l #1023,%d0
 bhi.w used_sample_absent
 rts
used_sample_absent:
 moveq #-1,%d0
 rts

/* (PatternLocks*, track, step, parameter slot) -> sample lock or -1.
 * A stock synth's parameter28 is not a sample reference. Select the same
 * saved/live Sound model as the DN2 pattern before calling its lock reader.
 */
used_sample_lock:
 lea -16(%sp),%sp
 movem.l %d2-%d4/%a2,(%sp)
 move.l 20(%sp),%d2
 subi.l #0x8b0,%d2
 move.l 24(%sp),%d3
 jsr 0x4018a97a
 move.l %d0,%d4
 move.l %d0,-(%sp)
 jsr 0x4003efa8
 addq.l #4,%sp
 cmp.l %d2,%d0
 bne.s used_lock_saved
 move.l %d4,%a0
 lea 244(%a0),%a0
 move.l %d3,-(%sp)
 move.l %a0,-(%sp)
 jsr 0x40030e66
 addq.l #8,%sp
 move.l %d0,%a0
 move.l (%a0),%a1
 move.l %a0,-(%sp)
 move.l 40(%a1),%a0
 jsr (%a0)
 addq.l #4,%sp
 bra.s used_lock_check_machine
used_lock_saved:
 move.l %d2,%d0
 sub.l %d4,%d0
 subi.l #0x4414,%d0
 move.l #0x954,%d1
 divu.l %d1,%d0
 move.l %d4,%a0
 lea 244(%a0),%a0
 move.l %d0,-(%sp)
 move.l %a0,-(%sp)
 jsr 0x4019172e
 addq.l #8,%sp
 tst.l %d0
 beq.s used_lock_absent
 move.l %d0,%a0
 move.l #1163,%d0
 mulu.l %d3,%d0
 lea 52(%a0,%d0.l),%a0
 move.l %a0,%d0
used_lock_check_machine:
 tst.l %d0
 beq.s used_lock_absent
 move.l %d0,%a0
 mvz.b 222(%a0),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.s used_lock_absent
 movem.l (%sp),%d2-%d4/%a2
 lea 16(%sp),%sp
 /* Reuse caller arguments, then bound the signed native result. */
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 jsr 0x4003cdba
 lea 16(%sp),%sp
 cmpi.l #1023,%d0
 bhi.w used_sample_absent
 rts
used_lock_absent:
 movem.l (%sp),%d2-%d4/%a2
 lea 16(%sp),%sp
 bra.w used_sample_absent
.balign 4
