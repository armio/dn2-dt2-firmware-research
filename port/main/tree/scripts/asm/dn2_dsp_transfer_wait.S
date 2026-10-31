/* Delay4013464C arms a hardware timer and blocks on its semaphore. Each
 * page gets one finite budget, shared by its header and all1024 words.
 * A partial page poisons the session: no later load may reuse its addresses.
 */
.global transfer_page,transfer_ready,transfer_fault,transfer_timeouts
.global transfer_delays,transfer_pages,transfer_budget,transfer_active
transfer_page:
 lea -20(%sp),%sp
 movem.l %d2-%d3/%a2-%a4,(%sp)
 tst.l transfer_fault
 bne.w page_reject
 move.l 24(%sp),%d3
 move.l 28(%sp),%a3
 move.l 32(%sp),%d2
 pea 0x42440964
 jsr 0x400015a0
 addq.l #4,%sp
 move.l #1000,%d0
 move.l %d0,transfer_budget
 moveq #1,%d0
 move.l %d0,transfer_active
 move.l %d3,-(%sp)
 bsr.w transfer_control
 addq.l #4,%sp
 tst.l %d0
 bne.s page_unlock
 lea transfer_control,%a2
 tst.l %d2
 bne.s page_words
 lea transfer_pcm,%a2
page_words:
 move.l #1024,%d2
page_word:
 move.l (%a3)+,-(%sp)
 jsr (%a2)
 addq.l #4,%sp
 tst.l %d0
 bne.s page_unlock
 subq.l #1,%d2
 bne.s page_word
 pea 100.w
 jsr 0x4013464c
 addq.l #4,%sp
 addq.l #1,transfer_pages
page_unlock:
 clr.l transfer_active
 pea 0x42440964
 jsr 0x400016d2
 addq.l #4,%sp
page_reject:
 move.l transfer_fault,%d0
 neg.l %d0
 movem.l (%sp),%d2-%d3/%a2-%a4
 lea 20(%sp),%sp
 rts

/* All encoded-word registers are preserved by the caller. */
transfer_ready:
 tst.l transfer_fault
 bne.s ready_failed
 tst.l transfer_active
 bne.s ready_poll
 move.l #1000,%d0
 move.l %d0,transfer_budget
ready_poll:
 move.w 0x8c000002,%d0
 btst #0,%d0
 bne.s ready_ok
 tst.l transfer_budget
 beq.s ready_timeout
 subq.l #1,transfer_budget
 addq.l #1,transfer_delays
 pea 1000.w
 jsr 0x4013464c
 addq.l #4,%sp
 bra.s ready_poll
ready_timeout:
 moveq #1,%d0
 move.l %d0,transfer_fault
 addq.l #1,transfer_timeouts
ready_failed:
 moveq #-1,%d0
 rts
ready_ok:
 moveq #0,%d0
 rts
transfer_word_fail:
 movem.l (%sp),%d2-%d7
 lea 24(%sp),%sp
 moveq #-1,%d0
 rts

/* The initial unload has its argument still on the stack. */
transfer_unload_failed:
 addq.l #4,%sp
 jmp LOAD_ERROR
transfer_reuse_failed:
 move.l %d2,-(%sp)
 jsr UNLOAD
 addq.l #4,%sp
 jmp LOAD_ERROR
/* New loads own two temporary buffers and an opened file at this stage.
 * Original unload removes the record association and clears its metadata;
 * sticky transport fault makes its descriptor cleanup return immediately.
 */
transfer_load_failed:
 pea -0x94(%a6)
 jsr FILE_CLOSE
 pea -0x98(%a6)
 jsr BUFFER_DESTROY
 pea -0x9c(%a6)
 jsr BUFFER_DESTROY
 lea 12(%sp),%sp
 bra.w transfer_reuse_failed
.balign 4
.global transfer_identity
transfer_identity: .long 0x54314436
transfer_fault: .long 0
transfer_timeouts: .long 0
transfer_delays: .long 0
transfer_pages: .long 0
transfer_budget: .long 0
transfer_active: .long 0
