/* Page event adapters. The final linker must bind sample_manager_open,
 * voice_page_open and sample_manager_event. Both open callbacks receive
 * (View *current, RawKeyEvent *event) and return whether the switch succeeded.
 * sample_manager_event is its View-subobject event thunk (not primary this).
 * VOICE is raw key0x32; bit0 is down, bit4 is clicked release, bit1 is FUNC.
 */
.text
.global voice_page_event
voice_page_event:
 movea.l 8(%sp),%a0
 move.l 12(%a0),%d0
 cmpi.l #0x32,%d0
 bne.s voice_original
 move.l 16(%a0),%d0
 btst #4,%d0
 beq.s voice_original
 btst #1,%d0
 bne.s voice_original
 jmp sample_manager_open
voice_original:
 jmp 0x40028dbe

.global sample_page_event
sample_page_event:
 movea.l 8(%sp),%a0
 move.l 12(%a0),%d0
 cmpi.l #0x32,%d0
 bne.s sample_original
 move.l 16(%a0),%d0
 btst #4,%d0
 beq.s sample_original
 btst #1,%d0
 beq.s sample_to_voice
 /* The native VOICE event handler's FUNC branch toggles current-track unison
  * and invalidates the common View. It uses no VoiceMenu-specific fields. */
 jmp 0x40028dbe
sample_to_voice:
 jmp voice_page_open
sample_original:
 jmp sample_manager_event
.balign 4
