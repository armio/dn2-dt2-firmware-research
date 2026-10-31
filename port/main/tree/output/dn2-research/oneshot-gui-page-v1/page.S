/* DT2 SourcePageView's compact layout on DN2 MultiSourcePageView.
 * Generated constants provide the separately verified native components.
 * The audio engine, sample loader, and native input methods are untouched.
 */
.text
.global os_gui_poll,os_gui_page_draw,os_gui_page_accessor,os_gui_page_end

/* Native page(type,index) prologue and fallback. Only type5 gains page1. */
os_gui_page_accessor:
move.l %d2,-(%sp)
moveq #4,%d2
move.l 8(%sp),%d1
cmpi.l #5,%d1
bne.s page_accessor_stock
move.l #0x42432bd4,%d0
move.l 12(%sp),%d2
cmpi.l #1,%d2
bhi.s page_accessor_done
move.l #0x47a38520,%d0
page_accessor_done:
move.l (%sp)+,%d2
rts
page_accessor_stock:
jmp 0x400c24f6

/* unsigned poll(workspace): bit0 cache ready; bit1 visible state changed.
 * Control installer returns bit0 ready, bit1 changed, with the same contract.
 */
os_gui_poll:
lea -12(%sp),%sp
movem.l %d2/%a2-%a3,(%sp)
movea.l 16(%sp),%a2
jsr os_controls_init
move.l %d0,%d2
andi.l #1,%d0
move.l %d0,0x68(%a2)
move.l %a2,-(%sp)
jsr os_wave_cache_poll
lea 4(%sp),%sp
andi.l #2,%d2
or.l %d2,%d0
movem.l (%sp),%d2/%a2-%a3
lea 12(%sp),%sp
rts

/* void draw(view,canvas,dispatch_value).
 * Parent fallback dispatch retains5 only for ONESHOT. Other values always
 * reach the original grid. Other parent branches never enter this function.
 */
os_gui_page_draw:
move.l 12(%sp),%d0
cmpi.l #5,%d0
bne.w draw_stock
movea.l 4(%sp),%a0
move.l 0x90(%a0),%d0
cmpi.l #1,%d0
bne.w draw_stock
tst.l 0x47a56c68
beq.w draw_stock
/* DT2 shows the ordinary value grid while the parameter-page key is held. */
move.l 0x6c(%a0),-(%sp)
jsr 0x40056122
lea 4(%sp),%sp
tst.b %d0
bne.w draw_stock
lea -64(%sp),%sp
movem.l %d2-%d7/%a2-%a6,(%sp)
movea.l 68(%sp),%a2
move.l 72(%sp),%d2
lea 0x94(%a2),%a3
movea.l %sp,%a4

/* Native DT2 clear: leave the left track/level area and outer header intact. */
clr.l -(%sp)
pea 52
pea 127
clr.l -(%sp)
pea 25
move.l %d2,-(%sp)
jsr 0x40114842
lea 24(%sp),%sp
moveq #24,%d3
clr.l %d5
column_loop:
clr.l %d4
row_loop:
move.l %d5,%d7
moveq #45,%d0
tst.l %d4
beq.s row_ready
addq.l #4,%d7
clr.l %d0
row_ready:
move.l %d0,60(%a4)
movea.l (%a2),%a0
movea.l 188(%a0),%a0
move.l %d7,-(%sp)
move.l %a2,-(%sp)
jsr (%a0)
lea 8(%sp),%sp
move.l %d0,%d6
beq.w empty_cell

clr.l 48(%a4)
pea 51(%a4)
move.l %d6,-(%sp)
move.l %a2,-(%sp)
jsr 0x4006538e
lea 12(%sp),%sp
move.l %d0,44(%a4)
move.l %d7,-(%sp)
move.l %a3,-(%sp)
jsr 0x40113558
lea 8(%sp),%sp
andi.l #255,%d0
move.l %d0,52(%a4)
move.l %d7,-(%sp)
move.l %a3,-(%sp)
jsr 0x40113346
lea 8(%sp),%sp
move.l %d0,56(%a4)

/* v45(view,canvas,x,y,id,value,edit,flag,knobflag,0,1).
 * These are the donor's exact compact-cell arguments and native handlers.
 */
movea.l (%a2),%a0
movea.l 180(%a0),%a5
pea 1
clr.l -(%sp)
move.l 52(%a4),-(%sp)
move.l 48(%a4),-(%sp)
move.l 56(%a4),-(%sp)
move.l 44(%a4),-(%sp)
move.l %d6,-(%sp)
move.l 60(%a4),-(%sp)
move.l %d3,-(%sp)
move.l %d2,-(%sp)
move.l %a2,-(%sp)
jsr (%a5)
lea 44(%sp),%sp
bra.s cell_done

empty_cell:
/* The sole empty descriptor is upper C. Match donor dotted rectangle. */
tst.l %d4
bne.s cell_done
pea 1
pea 50
move.l %d3,%d0
addi.l #17,%d0
move.l %d0,-(%sp)
pea 42
move.l %d3,%d0
addq.l #1,%d0
move.l %d0,-(%sp)
move.l %d2,-(%sp)
jsr 0x401147c2
lea 24(%sp),%sp
cell_done:
addq.l #1,%d4
cmpi.l #2,%d4
bne.w row_loop
addq.l #1,%d5
addi.l #26,%d3
cmpi.l #4,%d5
bne.w column_loop

/* Keep the native left level meter. */
movea.l (%a2),%a0
movea.l 184(%a0),%a0
clr.l -(%sp)
move.l %d2,-(%sp)
move.l %a2,-(%sp)
jsr (%a0)
lea 12(%sp),%sp
pea 0x47a56c00
move.l %d2,-(%sp)
move.l %a2,-(%sp)
jsr os_wave_draw
lea 12(%sp),%sp
tst.l %d0
bne.s page_dots

/* During an incomplete/failed load no waveform is asserted to be playable. */
lea unavailable,%a0
move.l 0x47a56004,%d0
cmpi.l #255,%d0
beq.s show_failed
cmpi.l #1,%d0
bcs.s show_state
cmpi.l #15,%d0
bhi.s show_state
lea loading,%a0
bra.s show_state
show_failed:
lea failed,%a0
show_state:
move.l %a0,-(%sp)
pea 2
pea 22
pea 73
pea 0x44507ed8
move.l %d2,-(%sp)
jsr 0x4011545c
lea 24(%sp),%sp

page_dots:
/* This branch is page1 of exactly2 ONESHOT pages. */
pea 7
pea 1
pea 2
move.l %d2,-(%sp)
move.l %a2,-(%sp)
jsr 0x4006598a
lea 20(%sp),%sp
movem.l (%sp),%d2-%d7/%a2-%a6
lea 64(%sp),%sp
rts
draw_stock:
jmp 0x40017428

loading: .asciz "LOADING"
failed: .asciz "LOAD ERROR"
unavailable: .asciz "WAVE UNAVAILABLE"
.balign 4
os_gui_page_end:
