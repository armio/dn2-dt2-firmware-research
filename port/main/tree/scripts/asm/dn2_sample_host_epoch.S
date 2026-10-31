/* Copy the original bool() job into a generation-stamped std::function.
 * Original captures, invocation and completion semantics remain intact. */
.text
.global sample_host_enqueue,sample_host_epoch_invoke,sample_host_epoch_manager
.global sample_host_epoch_type
sample_host_enqueue:
 link.w %a6,#-32
 movem.l %d2/%a2-%a4,(%sp)
 movea.l 16(%a6),%a3
 movea.l (%a3),%a4
 pea 32.w
 jsr 0x40120264
 addq.l #4,%sp
 movea.l %d0,%a2
 movea.l (%a4),%a0
 move.l 0x19c(%a0),(%a2)
 move.l %a0,12(%a2)
 move.l 0x446478d0,%d0
 clr.l 8(%a2)
 move.l 12(%a3),%d1
 cmpi.l #CLEAR_INVOKE,%d1
 bne.s enqueue_assignment
 moveq #1,%d1
 move.l %d1,8(%a2)
 bra.s enqueue_project
enqueue_assignment:
 move.l 4(%a4),%d0
enqueue_project:
 move.l %d0,4(%a2)
 move.l %a3,-(%sp)
 pea 16(%a2)
 jsr 0x401b40a2
 addq.l #8,%sp
 move.l %a2,-16(%a6)
 clr.l -12(%a6)
 move.l #sample_host_epoch_manager,%d0
 move.l %d0,-8(%a6)
 move.l #sample_host_epoch_invoke,%d0
 move.l %d0,-4(%a6)
 move.l 20(%a6),-(%sp)
 pea -16(%a6)
 move.l 12(%a6),-(%sp)
 move.l 8(%a6),-(%sp)
 jsr 0x400f2494
 lea 16(%sp),%sp
 move.l %d0,%d2
 pea -16(%a6)
 jsr 0x40188086
 addq.l #4,%sp
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a4
 unlk %a6
 rts

sample_host_epoch_invoke:
 move.l %a2,-(%sp)
 move.l %d2,-(%sp)
 movea.l 12(%sp),%a0
 movea.l (%a0),%a2
 pea RESTORE_LOCK
 jsr 0x40001608
 addq.l #4,%sp
 move.l HOST_EPOCH,%d0
 cmp.l (%a2),%d0
 bne.s invoke_stale
 move.l 0x446478d0,%d0
 cmp.l 4(%a2),%d0
 bne.s invoke_stale
 pea 16(%a2)
 movea.l 28(%a2),%a0
 jsr (%a0)
 addq.l #4,%sp
 move.l %d0,%d2
 bra.s invoke_unlock
invoke_stale:
 moveq #0,%d2
 tst.l 8(%a2)
 beq.s invoke_unlock
 /* A cancelled compaction must also finish its original polling state.
  * No samples were processed; the original response reports count zero. */
 movea.l 12(%a2),%a0
 clr.l 0x198(%a0)
 moveq #1,%d0
 move.b %d0,0x195(%a0)
invoke_unlock:
 pea RESTORE_LOCK
 jsr 0x4000172a
 addq.l #4,%sp
 move.l %d2,%d0
 move.l (%sp)+,%d2
 movea.l (%sp)+,%a2
 rts

/* std::function manager ABI: type=0,pointer=1,clone=2,destroy=3. */
sample_host_epoch_manager:
 move.l %a4,-(%sp)
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 movea.l 16(%sp),%a2
 movea.l 20(%sp),%a3
 move.l 24(%sp),%d0
 tst.l %d0
 beq.s manager_type
 subq.l #1,%d0
 beq.s manager_pointer
 subq.l #1,%d0
 beq.s manager_clone
 subq.l #1,%d0
 bne.s manager_done
 movea.l (%a2),%a4
 pea 16(%a4)
 jsr 0x40188086
 move.l %a4,-(%sp)
 jsr 0x40120270
 addq.l #8,%sp
 bra.s manager_done
manager_type:
 move.l #sample_host_epoch_type,(%a2)
 bra.s manager_done
manager_pointer:
 move.l (%a3),(%a2)
 bra.s manager_done
manager_clone:
 movea.l (%a3),%a3
 pea 32.w
 jsr 0x40120264
 addq.l #4,%sp
 movea.l %d0,%a4
 move.l (%a3),(%a4)
 move.l 4(%a3),4(%a4)
 move.l 8(%a3),8(%a4)
 move.l 12(%a3),12(%a4)
 pea 16(%a3)
 pea 16(%a4)
 jsr 0x401b40a2
 addq.l #8,%sp
 move.l %a4,(%a2)
manager_done:
 moveq #0,%d0
 movea.l (%sp)+,%a2
 movea.l (%sp)+,%a3
 movea.l (%sp)+,%a4
 rts
.balign 4
sample_host_epoch_type:
 .long 0x4020eeb4,sample_host_epoch_name
sample_host_epoch_name:
 .asciz "22Dn2SampleGenerationJob"
.balign 4
