/* Native UI event dispatch bridge. Keep the original jump table for every
 * event except DT2 SampleLoaded (31) and SampleUnloaded (32). The original
 * DT2 case bodies use frame locals and d2/d3 aliases, so provide their own
 * frame rather than borrowing DN2 UI task locals. */
.text
.global waveform_event_dispatch
waveform_event_dispatch:
 cmpi.l #31,%d0
 beq.s waveform_event_enter
 cmpi.l #32,%d0
 beq.s waveform_event_enter
 move.l %a0,-(%sp)
 lea 0x4002f19a,%a0
 move.w (%a0,%d0.l*2),%d0
 ext.l %d0
 movea.l (%sp)+,%a0
 jmp 0x4002f196
waveform_event_enter:
 lea -60(%sp),%sp
 movem.l %d0-%d7/%a0-%a6,(%sp)
 link.w %a6,#-96
 lea -44(%a6),%a0
 move.l %a0,%d2
 lea -88(%a6),%a0
 move.l %a0,%d3
 cmpi.l #31,%d0
 bne.s waveform_event_unload
 jmp 0x400344a8
waveform_event_unload:
 jmp 0x4003450a
.balign 4
