/* Browser int() jobs retain original captures and void(int) UI completion.
 * Reject work from an earlier project before any original worker executes. */
.text
.global browser_job_enqueue,browser_job_invoke,browser_job_manager
.global browser_barrier_enqueue,browser_barrier_invoke
browser_job_enqueue:
 moveq #0,%d1
 bra.s browser_enqueue_common
browser_barrier_enqueue:
 moveq #1,%d1
browser_enqueue_common:
 link.w %a6,#-32
 movem.l %d2-%d3/%a2-%a3,(%sp)
 move.l %d1,%d3
 movea.l 16(%a6),%a3
 tst.l %d3
 beq.s enqueue_capture
 movea.l 20(%a6),%a3
enqueue_capture:
 pea 24.w
 jsr 0x40120264
 addq.l #4,%sp
 movea.l %d0,%a2
 pea PROJECT_LOCK
 jsr 0x40001608
 addq.l #4,%sp
 move.l PROJECT_EPOCH,(%a2)
 move.l 0x446478d0,%d0
 move.l %d0,4(%a2)
 pea PROJECT_LOCK
 jsr 0x4000172a
 addq.l #4,%sp
 move.l %a3,-(%sp)
 pea 8(%a2)
 jsr 0x4018b180
 addq.l #8,%sp
 move.l %a2,-16(%a6)
 clr.l -12(%a6)
 move.l #browser_job_manager,%d0
 move.l %d0,-8(%a6)
 move.l #browser_job_invoke,%d0
 tst.l %d3
 beq.s enqueue_invoke
 move.l #browser_barrier_invoke,%d0
enqueue_invoke:
 move.l %d0,-4(%a6)
 tst.l %d3
 bne.s enqueue_barrier
 move.l 20(%a6),-(%sp)
 pea -16(%a6)
 bra.s enqueue_native
enqueue_barrier:
 pea -16(%a6)
 move.l 16(%a6),-(%sp)
enqueue_native:
 move.l 12(%a6),-(%sp)
 move.l 8(%a6),-(%sp)
 jsr 0x400f2494
 lea 16(%sp),%sp
 move.l %d0,%d2
 pea -16(%a6)
 jsr 0x40188086
 addq.l #4,%sp
 move.l %d2,%d0
 movem.l (%sp),%d2-%d3/%a2-%a3
 unlk %a6
 rts

browser_job_invoke:
 move.l %a2,-(%sp)
 move.l %d2,-(%sp)
 movea.l 12(%sp),%a0
 movea.l (%a0),%a2
 pea PROJECT_LOCK
 jsr 0x40001608
 addq.l #4,%sp
 moveq #0,%d2
 move.l PROJECT_EPOCH,%d0
 cmp.l (%a2),%d0
 bne.s job_unlock
 move.l 0x446478d0,%d0
 cmp.l 4(%a2),%d0
 bne.s job_unlock
 pea 8(%a2)
 movea.l 20(%a2),%a0
 jsr (%a0)
 addq.l #4,%sp
 move.l %d0,%d2
job_unlock:
 pea PROJECT_LOCK
 jsr 0x4000172a
 addq.l #4,%sp
 move.l %d2,%d0
 move.l (%sp)+,%d2
 movea.l (%sp)+,%a2
 rts

/* The barrier's worker is the original constant-true job. Its UI continuation
 * creates a subsequent load job; skip that continuation if its project left.
 * Queue-owned std::function destruction still releases the original captures. */
browser_barrier_invoke:
 move.l %a2,-(%sp)
 move.l %d2,-(%sp)
 movea.l 12(%sp),%a0
 movea.l (%a0),%a2
 pea PROJECT_LOCK
 jsr 0x40001608
 addq.l #4,%sp
 moveq #0,%d2
 move.l PROJECT_EPOCH,%d0
 cmp.l (%a2),%d0
 bne.s barrier_unlock
 move.l 0x446478d0,%d0
 cmp.l 4(%a2),%d0
 bne.s barrier_unlock
 move.l 16(%sp),-(%sp)
 pea 8(%a2)
 movea.l 20(%a2),%a0
 jsr (%a0)
 addq.l #8,%sp
 move.l %d0,%d2
barrier_unlock:
 pea PROJECT_LOCK
 jsr 0x4000172a
 addq.l #4,%sp
 move.l %d2,%d0
 move.l (%sp)+,%d2
 movea.l (%sp)+,%a2
 rts

browser_job_manager:
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
 pea 8(%a4)
 jsr 0x40188086
 move.l %a4,-(%sp)
 jsr 0x40120270
 addq.l #8,%sp
 bra.s manager_done
manager_type:
 move.l #browser_job_type,(%a2)
 bra.s manager_done
manager_pointer:
 move.l (%a3),(%a2)
 bra.s manager_done
manager_clone:
 movea.l (%a3),%a3
 pea 24.w
 jsr 0x40120264
 addq.l #4,%sp
 movea.l %d0,%a4
 move.l (%a3),(%a4)
 move.l 4(%a3),4(%a4)
 pea 8(%a3)
 pea 8(%a4)
 jsr 0x4018b180
 addq.l #8,%sp
 move.l %a4,(%a2)
manager_done:
 moveq #0,%d0
 movea.l (%sp)+,%a2
 movea.l (%sp)+,%a3
 movea.l (%sp)+,%a4
 rts
.balign 4
browser_job_type: .long 0x4020eeb4,browser_job_name
browser_job_name: .asciz "23Dn2BrowserGenerationJob"
.balign 4
