/* Keep the original DT2 SAMPLING+YES/NO callback scoped to Recorder.
 * DN2 VOICE has the same raw key (0x32). A modifier chord must consume
 * VOICE release rather than advancing pages. Consume YES/NO release even
 * if VOICE is released first, so that it cannot become a plain SAVE. */
.text
.global recorder_shortcut_route
recorder_shortcut_route:
 movea.l 4(%sp),%a0
 cmpa.l shortcut_owner,%a0
 beq.s owner_ready
 move.l %a0,shortcut_owner
 clr.l shortcut_used
 clr.l shortcut_key
owner_ready:
 movea.l 8(%sp),%a0
 move.l 12(%a0),%d0
 cmpi.l #0x32,%d0
 bne.s other_key
 move.l 16(%a0),%d0
 btst #1,%d0
 bne.s original
 btst #0,%d0
 beq.s voice_up
 btst #3,%d0
 bne.s original
 clr.l shortcut_used
 clr.l shortcut_key
 bra.s original
voice_up:
 tst.l shortcut_used
 beq.s original
 clr.l shortcut_used
 bra.s consumed
other_key:
 cmp.l shortcut_key,%d0
 bne.s donor
 move.l 16(%a0),%d0
 btst #0,%d0
 bne.s donor
 clr.l shortcut_key
 bra.s consumed
donor:
 move.l 8(%sp),-(%sp)
 move.l 8(%sp),-(%sp)
 jsr recorder_shortcut_event
 addq.l #8,%sp
 tst.b %d0
 beq.s original
 moveq #1,%d0
 move.l %d0,shortcut_used
 movea.l 8(%sp),%a0
 move.l 12(%a0),%d0
 move.l %d0,shortcut_key
consumed:
 moveq #1,%d0
 rts
original:
 jmp recorder_previous_route
.balign 4
.global shortcut_owner
shortcut_owner: .long 0
.global shortcut_used
shortcut_used: .long 0
.global shortcut_key
shortcut_key: .long 0
