/* Third VOICE page. Native keys emit DOWN=1, then clicked UP=0x10.
 * Consume VOICE down before the DT2 manager's generic key handler closes it;
 * change pages on clicked up, matching the native DN2 Voice page. */
.text
.global sample_to_recorder_event
sample_to_recorder_event:
 movea.l 8(%sp),%a0
 move.l 12(%a0),%d0
 cmpi.l #0x32,%d0
 bne.s manager_original
 move.l 16(%a0),%d0
 btst #1,%d0
 bne.s native_unison
 btst #4,%d0
 beq.s voice_pending
 jmp recorder_page_open
voice_pending:
 moveq #1,%d0
 rts
manager_original:
 jmp sample_manager_event
native_unison:
 jmp 0x40028dbe

.global recorder_page_event
recorder_page_event:
 movea.l 8(%sp),%a0
 move.l 12(%a0),%d0
 cmpi.l #0x32,%d0
 bne.s recorder_original
 move.l 16(%a0),%d0
 btst #1,%d0
 bne.s native_unison
 btst #4,%d0
 beq.s voice_pending
 jmp voice_page_open
recorder_original:
 jmp recorder_event

.global recorder_page_open
recorder_page_open:
 link.w %a6,#-24
 movem.l %d2-%d3/%a2,-24(%a6)
 movea.l 8(%a6),%a2
 move.l 44(%a2),%d2
 beq.s page_failed
 clr.l -8(%a6)
 clr.l -4(%a6)
 pea -4(%a6)
 jsr recorder_factory
 addq.l #4,%sp
 movea.l -4(%a6),%a0
 move.l %a0,%d0
 beq.s page_no_owner
 move.l 12(%a0),-8(%a6)
 jsr recorder_transport_open
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
 bra.s page_release
page_no_owner:
 clr.l %d3
page_release:
 pea -4(%a6)
 jsr 0x401880cc
 addq.l #4,%sp
 move.l %d3,%d0
 bra.s page_return
page_failed:
 clr.l %d0
page_return:
 movem.l -24(%a6),%d2-%d3/%a2
 unlk %a6
 rts

/* Only complete view destruction stops capture; trim/name dialogs do not. */
.global recorder_destroy_hook
recorder_destroy_hook:
 jsr recorder_transport_close
 move.l %a2,-(%sp)
 move.l #recorder_secondary_vtable,%d0
 jmp recorder_destroy_resume
.balign 4
