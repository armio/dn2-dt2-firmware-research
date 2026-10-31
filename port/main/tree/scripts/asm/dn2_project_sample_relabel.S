/* Native project move/swap relabel cache nodes without copying payloads.
 * Keep companion slot tags with their physical payload, and validate both
 * nodes before publishing either relabel.
 */
.text
.global sample_cache_move,sample_cache_swap,sample_cache_sync_slots
sample_cache_move:
 move.l #NATIVE_MOVE,%a0
 bra.s cache_relabel_call
sample_cache_swap:
 move.l #NATIVE_SWAP,%a0
cache_relabel_call:
 lea -8(%sp),%sp
 movem.l %d2/%a2,(%sp)
 move.l %a0,%a2
 move.l 20(%sp),-(%sp)
 move.l 20(%sp),-(%sp)
 move.l 20(%sp),-(%sp)
 jsr (%a2)
 lea 12(%sp),%sp
 move.l %d0,%d2
 tst.b %d2
 beq.s cache_relabel_done
 jsr sample_cache_sync_slots
 tst.l %d0
 bne.s cache_relabel_done
 moveq #0,%d2
cache_relabel_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2
 addq.l #8,%sp
 rts
sample_cache_sync_slots:
 lea -16(%sp),%sp
 movem.l %d2/%a2-%a4,(%sp)
 move.l #0x42c71a80,%a2
 suba.l %a3,%a3
 suba.l %a4,%a4
 moveq #0,%d2
cache_sync_validate:
 tst.b 4(%a2)
 beq.s cache_sync_next
 lea 12(%a2),%a0
 move.l %a0,-(%sp)
 jsr CACHE_ENTRY
 addq.l #4,%sp
 tst.l %d0
 beq.s cache_sync_fail
 move.l %d0,%a0
 tst.l 4(%a0)
 beq.s cache_sync_fail
 move.l 36(%a2),%d0
 cmp.l 8(%a0),%d0
 bne.s cache_sync_fail
 tst.l %d2
 bne.s cache_sync_second
 move.l %a0,%a3
 bra.s cache_sync_next
cache_sync_second:
 move.l %a0,%a4
cache_sync_next:
 move.l #0x438bca90,%a2
 addq.l #1,%d2
 cmpi.l #2,%d2
 bne.s cache_sync_validate
 tst.l %a3
 beq.s cache_sync_publish_second
 move.l 0x42c71a80,(%a3)
cache_sync_publish_second:
 tst.l %a4
 beq.s cache_sync_success
 move.l 0x438bca90,(%a4)
cache_sync_success:
 moveq #1,%d0
 bra.s cache_sync_done
cache_sync_fail:
 moveq #0,%d0
cache_sync_done:
 movem.l (%sp),%d2/%a2-%a4
 lea 16(%sp),%sp
 rts
