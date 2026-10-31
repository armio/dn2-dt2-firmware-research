/* T1D2: watch the first Kit header during native startup. Never repair it. */
.text
.global boot_watch_kit,boot_watch_last,boot_watch_done,boot_watch_fault
boot_watch_kit: .long 0
boot_watch_last: .long 0
boot_watch_done: .long 0

/* D0=checkpoint, A1=original stack. D0/D1/A0/A1 are saved by caller. */
boot_watch_check:
 move.l boot_watch_kit,%a0
 tst.l %a0
 beq.w boot_watch_return
 tst.l boot_watch_done
 bne.w boot_watch_return
 move.l (%a0),%d1
 cmpi.l #0x401da8d8,%d1
 bne.w boot_watch_bad
 cmpi.l #0xc0,%d0
 bhs.w boot_watch_memory
 cmpi.l #7,%d0
 bne.w boot_watch_checkpoint
 move.l boot_watch_last,%d1
 cmpi.l #6,%d1
 blo.w boot_watch_return
 move.l 0x446478d0,%d1
 beq.w boot_watch_return
 addi.l #0xf4,%d1
 cmp.l %a0,%d1
 bne.w boot_watch_return
 moveq #1,%d1
 move.l %d1,boot_watch_done
boot_watch_checkpoint:
 move.l %d0,boot_watch_last
 bra.w boot_watch_return
boot_watch_memory:
 move.l 12(%a1),%d1
 beq.w boot_watch_return
 move.l %a0,%d1
 addq.l #4,%d1
 cmp.l 4(%a1),%d1
 bls.w boot_watch_return
 move.l 4(%a1),%d1
 add.l 12(%a1),%d1
 bcs.w boot_watch_bad
 cmp.l %a0,%d1
 bls.w boot_watch_return
boot_watch_bad:
 lea -48(%sp),%sp
 move.l %d0,4(%sp)
 move.l #0x54423244,%d0
 move.l %d0,(%sp)
 move.l %a0,8(%sp)
 move.l (%a0),%d0
 move.l %d0,12(%sp)
 move.l boot_watch_last,%d0
 move.l %d0,16(%sp)
 move.l 4(%a1),%d0
 move.l %d0,20(%sp)
 move.l 8(%a1),%d0
 move.l %d0,24(%sp)
 move.l 12(%a1),%d0
 move.l %d0,28(%sp)
 move.l (%a1),%d0
 move.l %d0,32(%sp)
 move.l 0x446478d0,%d0
 move.l %d0,36(%sp)
 move.l 4(%a0),%d0
 move.l %d0,40(%sp)
 move.l 0x44(%a0),%d0
 move.l %d0,44(%sp)
boot_watch_fault:
 .word 0x4afc
 bra.w boot_watch_fault
boot_watch_return:
 rts

.macro save_watch
 lea -20(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 move.w %sr,%d0
 move.l %d0,16(%sp)
 lea 20(%sp),%a1
.endm
.macro restore_watch
 move.l 16(%sp),%d0
 move.w %d0,%ccr
 movem.l (%sp),%d0-%d1/%a0-%a1
 lea 20(%sp),%sp
.endm
.global boot_watch_init
boot_watch_init:
 move.l #0x401da8d8,(%a2)
 save_watch
 tst.l boot_watch_kit
 bne.w boot_watch_init_done
 move.l %a2,boot_watch_kit
 moveq #1,%d0
 move.l %d0,boot_watch_last
boot_watch_init_done:
 restore_watch
 jmp 0x40032572

/* Generated checkpoint wrappers follow. */
