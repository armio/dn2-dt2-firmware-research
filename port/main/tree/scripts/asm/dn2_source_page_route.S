/* Resolve MainScreen's audio SYN entry to the original DT2 Source view.
 * Keep native stock and MIDI entries intact. Each page owns its own complete
 * C++ object and subscriptions; their extension fields must never overlap.
 */
.text
.global source_page_pair,source_open_pair_hook,source_get_pair_hook
.global source_route_cache
.global source_route_release,source_main_destroy_hook
source_page_pair:
 link.w %a6,#-48
 movem.l %d2/%a2-%a4,-48(%a6)
 movea.l 8(%a6),%a2
 movea.l 12(%a6),%a3
 lea 0x10c(%a2),%a0
 cmpa.l %a0,%a3
 bne.w pair_stock
 move.l (%a3),%d0
 beq.w pair_stock
 move.l %d0,-(%sp)
 jsr 0x4005a42e
 addq.l #4,%sp
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.w pair_stock
 lea source_route_cache,%a4
 tst.l 12(%a4)
 bne.w pair_stock
 cmpa.l (%a4),%a2
 bne.s pair_create
 tst.l 4(%a4)
 bne.w pair_cached
pair_create:
 moveq #1,%d0
 move.l %d0,12(%a4)
 clr.l -4(%a6)
 clr.l -8(%a6)
 clr.l -12(%a6)
 clr.l -16(%a6)
 moveq #2,%d0
 move.l %d0,-20(%a6)
 pea 8
 jsr 0x40120264
 addq.l #4,%sp
 tst.l %d0
 beq.s pair_failed
 movea.l %d0,%a0
 moveq #7,%d1
 move.l %d1,(%a0)+
 move.l %d1,(%a0)+
 move.l %d0,-16(%a6)
 move.l %a0,-12(%a6)
 move.l %a0,-8(%a6)
 pea -20(%a6)
 pea -16(%a6)
 clr.l -(%sp)
 clr.l -(%sp)
 clr.l -(%sp)
 pea -4(%a6)
 jsr source_factory
 lea 24(%sp),%sp
 pea -16(%a6)
 jsr 0x4018b1c6
 addq.l #4,%sp
 tst.l -4(%a6)
 beq.s pair_failed
 pea 8(%a4)
 jsr 0x401880cc
 addq.l #4,%sp
 movea.l -4(%a6),%a0
 move.l %a2,(%a4)
 move.l 12(%a0),4(%a4)
 move.l %a0,8(%a4)
 clr.l 12(%a4)
pair_cached:
 lea 4(%a4),%a0
 move.l %a0,%d0
 bra.s pair_return
pair_failed:
 clr.l 12(%a4)
pair_stock:
 move.l %a3,%d0
pair_return:
 movem.l -48(%a6),%d2/%a2-%a4
 unlk %a6
 rts

/* 4005E844 originally computes A3=A4+(D2*8). Keep volatile state,
 * especially A0, which the native empty-entry branch uses as a function. */
source_open_pair_hook:
 move.l %d2,%d0
 lsl.l #3,%d0
 lea (%a4,%d0.l),%a3
 lea -16(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 jsr source_page_pair
 addq.l #8,%sp
 movea.l %d0,%a3
 movem.l (%sp),%d0-%d1/%a0-%a1
 lea 16(%sp),%sp
 rts

/* 4005D14E computes the shared pair for get-current-page's hidden A0
 * result. D2 is that result pointer; A2 still holds MainScreen on entry. */
source_get_pair_hook:
 lea -20(%sp),%sp
 movem.l %d0-%d1/%a0-%a1/%a3,(%sp)
 movea.l %a2,%a3
 lsl.l #3,%d4
 movea.l %d1,%a2
 adda.l %d4,%a2
 move.l %a2,-(%sp)
 move.l %a3,-(%sp)
 jsr source_page_pair
 addq.l #8,%sp
 movea.l %d0,%a2
 movem.l (%sp),%d0-%d1/%a0-%a1/%a3
 lea 20(%sp),%sp
 movea.l %d2,%a1
 rts

/* MainScreen owns this extra cached page just as it owns its native pages.
 * Clear the cache before releasing its owner to make cleanup reentrant. */
source_route_release:
 lea source_route_cache,%a0
 movea.l 4(%sp),%a1
 cmpa.l (%a0),%a1
 bne.s source_release_done
 move.l 8(%a0),-(%sp)
 clr.l (%a0)
 clr.l 4(%a0)
 clr.l 8(%a0)
 clr.l 12(%a0)
 move.l %sp,-(%sp)
 jsr 0x401880cc
 addq.l #8,%sp
source_release_done:
 rts

source_main_destroy_hook:
 move.l 4(%sp),-(%sp)
 jsr source_route_release
 addq.l #4,%sp
 /* Replay the eight overwritten prologue bytes. */
 lea -12(%sp),%sp
 movem.l %a2-%a4,(%sp)
 jmp 0x4019e9ca
.balign 4
source_route_cache:
 .long 0,0,0,0
