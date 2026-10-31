/* T1D4: validate native heap free-list heads before use or publication.
 * Only the native allocator at 4029EB9C is watched, through initial Kit reset.
 * Head values are 16-byte unit indexes; -1 is the only empty-list sentinel.
 */
.text
.global boot_freelist_history,boot_freelist_get,boot_freelist_set
.global boot_freelist_fault
/* Per-order last successful native setter: caller,order,new head,old head. */
boot_freelist_history:
 .space 352

.macro save_freelist
 lea -36(%sp),%sp
 movem.l %d0-%d3/%a0-%a3,(%sp)
 move.w %sr,%d0
 move.l %d0,32(%sp)
 lea 36(%sp),%a1
.endm
.macro restore_freelist
 move.l 32(%sp),%d0
 move.w %d0,%ccr
 movem.l (%sp),%d0-%d3/%a0-%a3
 lea 36(%sp),%sp
.endm

/* A1 is the unmodified native entry stack. D1 order,D3 existing head. */
.macro prepare_freelist skip
 move.l 4(%a1),%d0
 cmpi.l #0x4029eb9c,%d0
 bne.w \skip
 tst.l WATCH_DONE
 bne.w \skip
 move.l 8(%a1),%d1
 tst.l %d1
 bmi.w \skip
 cmpi.l #21,%d1
 bhi.w \skip
 cmp.l 0x4029ebac,%d1
 bhi.w \skip
 move.l 0x4029eba8,%a0
 move.l (%a0,%d1.l*4),%d3
.endm

boot_freelist_get:
 save_freelist
 prepare_freelist freelist_get_done
 move.l %d3,%d2
 move.l #0x60,%a3
 bsr.w boot_freelist_validate
freelist_get_done:
 restore_freelist
 move.l 4(%sp),%a0
 move.l 8(%sp),%d0
 jmp 0x4011fe08

boot_freelist_set:
 save_freelist
 prepare_freelist freelist_set_done
 move.l 12(%a1),%d2
 move.l #0x70,%a3
 bsr.w boot_freelist_validate
 /* Record only accepted writes, immediately before replaying the setter. */
 move.l %d1,%d0
 lsl.l #4,%d0
 lea boot_freelist_history,%a0
 adda.l %d0,%a0
 move.l (%a1),%d0
 move.l %d0,(%a0)
 move.l %d1,4(%a0)
 move.l %d2,8(%a0)
 move.l %d3,12(%a0)
freelist_set_done:
 restore_freelist
 move.l 4(%sp),%a0
 move.l 8(%sp),%d0
 jmp 0x4011fe26

/* D1=order,D2=head,D3=old head,A3=reason base60/70.
 * Preserve these and A1; D0/A0/A2 are scratch. */
boot_freelist_validate:
 cmpi.l #-1,%d2
 beq.w freelist_valid
 tst.l %d2
 bmi.w freelist_invalid
 moveq #1,%d0
 lsl.l %d1,%d0
 move.l %d0,%a2
 subq.l #1,%d0
 and.l %d2,%d0
 bne.w freelist_invalid
 move.l 0x4029ebb0,%d0
 cmp.l %a2,%d0
 blo.w freelist_invalid
 sub.l %a2,%d0
 cmp.l %d2,%d0
 blo.w freelist_invalid
 move.l WATCH_PROJECT,%d0
 beq.w freelist_valid
 sub.l 0x4029eba0,%d0
 lsr.l #4,%d0
 addi.l #0x8000,%d0
 cmp.l %d2,%d0
 bls.w freelist_valid /* Project end <= free start. */
 subi.l #0x8000,%d0
 adda.l %d2,%a2
 cmp.l %a2,%d0
 bcc.w freelist_valid /* Project start >= free end. */
 move.l %a3,%d0
 addq.l #2,%d0
 bra.w boot_freelist_trap
freelist_invalid:
 move.l %a3,%d0
 addq.l #1,%d0
 bra.w boot_freelist_trap
freelist_valid:
 rts

/* Twelve screen words, copied before invoking the native exception screen. */
boot_freelist_trap:
 lea -48(%sp),%sp
 move.l %d0,4(%sp)
 move.l #0x54423444,%d0
 move.l %d0,(%sp)
 move.l WATCH_PROJECT,%d0
 move.l %d0,8(%sp)
 move.l (%a1),%d0
 move.l %d0,12(%sp)
 move.l %d1,16(%sp)
 move.l %d2,20(%sp)
 move.l %d3,24(%sp)
 move.l %d1,%d0
 lsl.l #4,%d0
 lea boot_freelist_history,%a0
 adda.l %d0,%a0
 move.l (%a0),%d0
 move.l %d0,28(%sp)
 move.l 4(%a0),%d0
 move.l %d0,32(%sp)
 move.l 8(%a0),%d0
 move.l %d0,36(%sp)
 move.l 12(%a0),%d0
 move.l %d0,40(%sp)
 move.l 0x4029eb9c,%d0
 move.l %d0,44(%sp)
boot_freelist_fault:
 .word 0x4afc
 bra.w boot_freelist_fault
.balign 4
