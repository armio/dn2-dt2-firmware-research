/* UI-task-only waveform component. No heap, filesystem or audio writes.
 * The private workspace is 0x240 bytes, aligned4 and cleared at startup.
 * Cache construction is a separate poll call and never occurs during draw.
 */
.equ WS_MAGIC, 0x50
.equ WS_ENTRY, 0x80
.equ WAVE_MAGIC, 0x4f535731
.equ LOAD_STATE, 0x47a56000
.equ BANK, 0x47a46000
.equ PCM, BANK+0x1014
.equ FRAMES, 2708
.equ FRAME_END_MIN, 2567
.equ FULL, 0x7800
.equ GET_VALUE, 0x4006538e
.text
.global os_wave_cache_poll,os_wave_draw,os_wave_native,os_wave_getter,os_wave_noop

/* int os_wave_cache_poll(void *workspace). Exactly96bins/2708frames once. */
os_wave_cache_poll:
lea -48(%sp),%sp
movem.l %d2-%d7/%a2-%a6,(%sp)
movea.l %sp@(52),%a2
move.l %a2@(0x5c),%sp@(44)
move.l LOAD_STATE+4,%d0
cmp.l %a2@(0x60),%d0
beq.s phase_same
move.l %d0,%a2@(0x60)
addq.l #1,%a2@(0x5c)
phase_same:
move.l LOAD_STATE+12,%d0
cmp.l %a2@(0x64),%d0
beq.s error_same
move.l %d0,%a2@(0x64)
addq.l #1,%a2@(0x5c)
error_same:
move.l LOAD_STATE,%d0
cmpi.l #0x4f534c31,%d0
bne.w cache_bad
move.l LOAD_STATE+4,%d0
beq.w cache_builtin
cmpi.l #16,%d0
bne.w cache_bad
tst.l LOAD_STATE+12
bne.w cache_bad
move.l LOAD_STATE+20,%d0
cmpi.l #47104,%d0
bne.w cache_bad
move.l LOAD_STATE+28,%d0
cmpi.l #47104,%d0
bne.w cache_bad
move.l LOAD_STATE+32,%d0
cmpi.l #0x508a4170,%d0
bne.w cache_bad
move.l LOAD_STATE+60,%d0
cmpi.l #21,%d0
bne.w cache_bad
move.l BANK,%d0
cmpi.l #0x4f534231,%d0
bne.w cache_bad
move.l BANK+4,%d0
cmpi.l #0x01000000,%d0
bne.w cache_bad
move.l BANK+8,%d0
cmpi.l #0x14183100,%d0
bne.w cache_bad
move.l BANK+12,%d0
cmpi.l #0x940a0000,%d0
bne.w cache_bad
move.l BANK+16,%d0
cmpi.l #0x80bb0000,%d0
bne.w cache_bad
move.l %a2@(WS_MAGIC),%d0
cmpi.l #WAVE_MAGIC,%d0
bne.s cache_rebuild
move.l %a2@(0x54),%d0
cmpi.l #FRAMES,%d0
beq.w cache_ready
cache_rebuild:
/* Clear the401-byte entry plus3pad bytes; publication remains invalid. */
lea %a2@(WS_ENTRY),%a4
movea.l %a4,%a0
moveq #101,%d0
cache_clear:
clr.l (%a0)+
subq.l #1,%d0
bne.s cache_clear
move.l %a4,%a2@(0x38)
move.l #FRAMES,%d0
move.l %d0,%a2@(0x54)
moveq #16,%d0
move.l %d0,%a2@(0x58)
lea PCM,%a3
clr.l %d2
clr.l %d3
clr.l %d4
cache_bin:
addi.l #FRAMES,%d4
move.l %d4,%d5
moveq #96,%d0
divu.l %d0,%d5
clr.l %d6
clr.l %d7
cache_sample:
clr.l %d0
clr.l %d1
move.b (%a3)+,%d0
move.b (%a3)+,%d1
lsl.l #8,%d1
or.l %d1,%d0
ext.l %d0
asr.l #8,%d0
cmp.l %d6,%d0
ble.s no_max
move.l %d0,%d6
no_max:
cmp.l %d7,%d0
bge.s no_min
move.l %d0,%d7
no_min:
addq.l #1,%d3
cmp.l %d5,%d3
bcs.s cache_sample
move.b %d6,%a4@(0x10,%d2:l)
move.b %d7,%a4@(0x70,%d2:l)
addq.l #1,%d2
cmpi.l #96,%d2
bne.s cache_bin
move.l #WAVE_MAGIC,%d0
move.l %d0,%a2@(WS_MAGIC)
addq.l #1,%a2@(0x5c)
bra.s cache_ready
cache_builtin:
tst.l LOAD_STATE+8
bne.s cache_bad
tst.l LOAD_STATE+12
bne.s cache_bad
move.l %a2@(WS_MAGIC),%d0
cmpi.l #WAVE_MAGIC,%d0
bne.s builtin_copy
move.l %a2@(0x54),%d0
cmpi.l #7200,%d0
beq.s cache_ready
builtin_copy:
lea os_wave_builtin_cache,%a0
lea %a2@(WS_ENTRY),%a1
move.l %a1,%a2@(0x38)
moveq #101,%d0
builtin_words:
move.l (%a0),(%a1)+
lea %a0@(4),%a0
subq.l #1,%d0
bne.s builtin_words
move.l #7200,%d0
move.l %d0,%a2@(0x54)
clr.l %a2@(0x58)
move.l #WAVE_MAGIC,%d0
move.l %d0,%a2@(WS_MAGIC)
addq.l #1,%a2@(0x5c)
cache_ready:
moveq #1,%d0
bra.s cache_done
cache_bad:
tst.l %a2@(WS_MAGIC)
beq.s cache_was_bad
clr.l %a2@(WS_MAGIC)
addq.l #1,%a2@(0x5c)
cache_was_bad:
clr.l %d0
cache_done:
move.l %a2@(0x5c),%d1
cmp.l %sp@(44),%d1
beq.s flags_done
ori.l #2,%d0
flags_done:
movem.l (%sp),%d2-%d7/%a2-%a6
lea 48(%sp),%sp
rts

/* int os_wave_draw(void *view,void *canvas,void *workspace).
 * Reads native values and calls the resident byte-identical DT2 marker setter,
 * renders exactly native widget body/markers. Playback cursor stays disabled.
 */
os_wave_draw:
lea -48(%sp),%sp
movem.l %d2-%d7/%a2-%a6,(%sp)
movea.l %sp@(52),%a3
movea.l %sp@(56),%a4
movea.l %sp@(60),%a2
move.l %a2@(WS_MAGIC),%d0
cmpi.l #WAVE_MAGIC,%d0
bne.w draw_unready
/* Recheck readiness without touching or scanning the PCM/cache. */
move.l LOAD_STATE,%d0
cmpi.l #0x4f534c31,%d0
bne.w draw_unready
move.l LOAD_STATE+4,%d0
cmp.l %a2@(0x58),%d0
bne.w draw_unready
tst.l %d0
beq.s draw_phase_ok
cmpi.l #16,%d0
bne.w draw_unready
draw_phase_ok:
tst.l LOAD_STATE+12
bne.w draw_unready
clr.l (%a2)
clr.l %a2@(0x14)
clr.b %a2@(0x18)
move.l #25,%d0
move.l %d0,%a2@(0x1c)
move.l #8,%d0
move.l %d0,%a2@(0x20)
move.l #96,%d0
move.l %d0,%a2@(0x24)
move.l #32,%d0
move.l %d0,%a2@(0x28)
move.b #1,%a2@(0x30)
move.b #1,%a2@(0x31)
move.b #1,%a2@(0x32)
lea %sp@(44),%a5
/* GET_VALUE(view,id,&flag), native complete u16parameter values. */
move.l %a5,-(%sp)
pea 5
move.l %a3,-(%sp)
jsr GET_VALUE
lea 12(%sp),%sp
move.l %d0,%d2
move.l %a5,-(%sp)
pea 11
move.l %a3,-(%sp)
jsr GET_VALUE
lea 12(%sp),%sp
move.l %d0,%d3
move.l %a5,-(%sp)
pea 12
move.l %a3,-(%sp)
jsr GET_VALUE
lea 12(%sp),%sp
/* DT2 SourcePageView 400177CE..400177F4: signed LOOP minus 0x100,
 * marker enabled only if positive. Marker visibility is independent of PLAY.
 * Native DN2 setter 401103E4 exactly matches donor4010EA70 (136 bytes).
 * Parameters remain native raw positions, not effective DSP sample bounds.
 */
subi.l #0x100,%d0
move.l %d0,%d4
tst.l %d4
sgt %d0
extb.l %d0
neg.l %d0
move.l %d0,-(%sp)
move.l %d4,-(%sp)
move.l %d3,-(%sp)
move.l %d2,-(%sp)
move.l %a2,-(%sp)
jsr 0x401103e4
lea 20(%sp),%sp
move.l %a4,-(%sp)
move.l %a2,-(%sp)
jsr os_wave_native
addq.l #8,%sp
moveq #1,%d0
bra.s draw_done
draw_unready:
clr.l %d0
draw_done:
movem.l (%sp),%d2-%d7/%a2-%a6
lea 48(%sp),%sp
rts

/* Only the copied renderer calls this; A2is its52Bwidget/workspace. */
os_wave_getter:
move.l %a2,%d0
addi.l #0x34,%d0
rts
os_wave_noop:
rts
.balign 4
os_wave_native:
.incbin "native-render.bin"
.balign 4
os_wave_builtin_cache:
.incbin "builtin-cache.bin"
.global os_wave_code_end
os_wave_code_end:
