/* Native page factories and controller handoff. Included after route adapters.
 * Final linker binds sample_manager_factory to the transplanted DT2 factory.
 * Current is always the common View subobject, including SampleManager+0x38.
 * Close marks the old view for controller cleanup; it does not destroy this
 * handler's object inline. Keep the new shared owner until controller adoption.
 */
.text
.global sample_manager_open
.global voice_page_open
sample_manager_open:
 link.w %a6,#-40
 movem.l %d2-%d3/%a2,-40(%a6)
 movea.l 8(%a6),%a2
 move.l 44(%a2),%d2
 beq.w page_open_failed
 clr.l -8(%a6)
 clr.l -4(%a6)
 clr.l -12(%a6)
 move.b #1,-11(%a6)
 move.b #1,-10(%a6)
 clr.l -28(%a6)
 clr.l -24(%a6)
 clr.l -20(%a6)
 clr.l -16(%a6)
 pea -10(%a6)
 pea -28(%a6)
 pea -11(%a6)
 pea -12(%a6)
 lea -8(%a6),%a0
 jsr sample_manager_factory
 lea 16(%sp),%sp
 move.l -8(%a6),%d0
 beq.s page_release
 addi.l #0x38,%d0
 move.l %d0,-8(%a6)
 bra.s page_adopt
voice_page_open:
 link.w %a6,#-40
 movem.l %d2-%d3/%a2,-40(%a6)
 movea.l 8(%a6),%a2
 move.l 44(%a2),%d2
 beq.s page_open_failed
 clr.l -8(%a6)
 clr.l -4(%a6)
 pea -4(%a6)
 jsr 0x4019f232
 addq.l #4,%sp
 movea.l -4(%a6),%a0
 move.l %a0,%d0
 beq.s page_release
 move.l 12(%a0),-8(%a6)
page_adopt:
 /* Mark the outgoing page closed before enqueueing the new one. */
 movea.l (%a2),%a0
 movea.l 40(%a0),%a0
 move.l %a2,-(%sp)
 jsr (%a0)
 addq.l #4,%sp
 clr.l -(%sp)
 pea -8(%a6)
 move.l %d2,-(%sp)
 jsr 0x4011d71e
 lea 12(%sp),%sp
 move.l %d0,%d3
 bra.s page_release_owner
page_release:
 clr.l %d3
page_release_owner:
 pea -4(%a6)
 jsr 0x401880cc
 addq.l #4,%sp
 move.l %d3,%d0
 bra.s page_open_return
page_open_failed:
 clr.l %d0
page_open_return:
 movem.l -40(%a6),%d2-%d3/%a2
 unlk %a6
 rts
.balign 4
