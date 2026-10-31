/* Source/SLICE use track numbers; DN2 audio replies use physical voices.
 * Prefer the allocator's last voice, then an active remaining owned voice.
 * No allocator state or sound parameters are modified here.
 */
.text
.global cursor_track_voice,cursor_track_coarse,cursor_track_fine,cursor_track_active
cursor_track_voice:
 link.w %a6,#-8
 movem.l %d2/%a2,-8(%a6)
 move.l 8(%a6),%d2
 cmpi.l #15,%d2
 bhi.s cursor_no_voice
 move.l %d2,-(%sp)
 jsr 0x4002b20e
 addq.l #4,%sp
 lea 0x80005308,%a2
 cmpi.l #15,%d0
 bhi.s cursor_scan
 cmp.l (%a2,%d0.l*4),%d2
 bne.s cursor_scan
 lea 0x800024bc,%a0
 tst.w (%a0,%d0.l*2)
 bpl.s cursor_voice_return
cursor_scan:
 moveq #0,%d0
 lea 0x800024bc,%a0
cursor_next:
 cmp.l (%a2,%d0.l*4),%d2
 bne.s cursor_skip
 tst.w (%a0,%d0.l*2)
 bpl.s cursor_voice_return
cursor_skip:
 addq.l #1,%d0
 cmpi.l #16,%d0
 bne.s cursor_next
cursor_no_voice:
 moveq #-1,%d0
cursor_voice_return:
 movem.l -8(%a6),%d2/%a2
 unlk %a6
 rts

.macro reader name,native
\name:
 move.l 4(%sp),-(%sp)
 jsr cursor_track_voice
 addq.l #4,%sp
 tst.l %d0
 bmi.s 1f
 move.l %d0,-(%sp)
 jsr \native
 addq.l #4,%sp
 rts
1:
 moveq #0,%d0
 rts
.endm
reader cursor_track_coarse,0x400cfa98
reader cursor_track_fine,0x400cfab8
reader cursor_track_active,0x400cfad6
.balign 4
