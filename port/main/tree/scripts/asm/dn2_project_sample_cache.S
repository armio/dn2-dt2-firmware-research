/* Companion state for the two fixed native project-cache nodes.
 * Each entry: slot+0, ready+4, uid+8, reserved+C, record+10 (4200 bytes).
 * Separate heap storage avoids moving any native project memory.
 */
.text
.global sample_cache_entry,sample_cache_reset,sample_cache_acquire
.global sample_cache_blank,sample_cache_read,sample_cache_write,sample_cache_load
sample_cache_entry:
 move.l %d2,-(%sp)
 move.l 8(%sp),%d0
 moveq #0,%d2
 cmpi.l #0x42c71a8c,%d0
 beq.s cache_entry_known
 move.l #0x4210,%d2
 cmpi.l #0x438bca9c,%d0
 bne.s cache_entry_unknown
cache_entry_known:
 move.l CACHE_STATE,%d0
 bne.s cache_entry_ready
 move.l #0x8420,-(%sp)
 jsr 0x40120264
 addq.l #4,%sp
 tst.l %d0
 beq.s cache_entry_unknown
 move.l %a2,-(%sp)
 move.l %d0,%a2
 move.l #0x8420,-(%sp)
 clr.l -(%sp)
 move.l %a2,-(%sp)
 jsr 0x401344d8
 lea 12(%sp),%sp
 move.l %a2,CACHE_STATE
 move.l %a2,%d0
 move.l (%sp)+,%a2
cache_entry_ready:
 add.l %d2,%d0
 move.l (%sp)+,%d2
 rts
cache_entry_unknown:
 moveq #0,%d0
 move.l (%sp)+,%d2
 rts

/* (entry*, native serialized cache buffer*) -> empty, ready companion. */
sample_cache_reset:
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 move.l 16(%sp),%a2
 move.l 20(%sp),%a3
 clr.l 4(%a2)
 move.l -12(%a3),(%a2)
 move.l 24(%a3),%d2
 move.l %d2,8(%a2)
 lea 528(%a2),%a3
 move.l #16384,-(%sp)
 moveq #-1,%d0
 move.l %d0,-(%sp)
 move.l %a3,-(%sp)
 jsr 0x401344d8
 lea 12(%sp),%sp
 move.l %a3,-(%sp)
 move.l %d2,-(%sp)
 lea 16(%a2),%a0
 move.l %a0,-(%sp)
 jsr RECORD_PREPARE
 lea 12(%sp),%sp
 moveq #1,%d0
 move.l %d0,4(%a2)
 moveq #0,%d0
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts

/* Native reuse/eviction: commit outgoing node before invalidating its table. */
sample_cache_acquire:
 lea -32(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 move.l 36(%sp),%d2
 /* Match the native two-entry selection before allowing eviction. */
 move.l #0x42c71a80,%a2
 tst.b 4(%a2)
 beq.s cache_acquire_selected
 tst.b 0x438bca94
 beq.s cache_acquire_second
 tst.b 5(%a2)
 beq.s cache_acquire_selected
 tst.b 0x438bca95
 bne.s cache_acquire_selected
cache_acquire_second:
 move.l #0x438bca90,%a2
cache_acquire_selected:
 lea 12(%a2),%a0
 move.l %a0,-(%sp)
 jsr sample_cache_entry
 addq.l #4,%sp
 tst.l %d0
 beq.w cache_acquire_failed
 move.l %d0,%a3
 tst.b 4(%a2)
 beq.s cache_acquire_native
 tst.b 6(%a2)
 beq.s cache_acquire_native
 clr.l 16(%sp)
 clr.l 20(%sp)
 clr.l 24(%sp)
 clr.l 28(%sp)
 lea 16(%sp),%a0
 move.l %a0,-(%sp)
 move.l %a2,-(%sp)
 move.l %d2,-(%sp)
 jsr 0x400f659c
 lea 12(%sp),%sp
 tst.b %d0
 bne.s cache_acquire_native
 /* Native commit invalidates on failure. Retain the dirty source for retry. */
 moveq #1,%d0
 move.b %d0,4(%a2)
 move.b %d0,6(%a2)
 bra.s cache_acquire_failed
cache_acquire_native:
 move.l 40(%sp),-(%sp)
 move.l %d2,-(%sp)
 jsr NATIVE_ACQUIRE
 addq.l #8,%sp
 tst.l %d0
 beq.s cache_acquire_done
 move.l %d0,%a2
 clr.l 4(%a3)
 move.l (%a2),(%a3)
 bra.s cache_acquire_done
cache_acquire_failed:
 moveq #0,%d0
cache_acquire_done:
 movem.l (%sp),%d2/%a2-%a3
 lea 32(%sp),%sp
 rts

/* Native load assumes acquisition cannot fail. Preflight it here so a failed
 * companion commit never lets that native caller dereference a null node.
 * The acquired node remains invalid, and native load reuses the same node.
 */
sample_cache_load:
 lea -8(%sp),%sp
 movem.l %d2/%a2,(%sp)
 move.l 12(%sp),%a2
 move.l 16(%sp),%d2
 cmpi.l #128,%d2
 bhi.s cache_load_failed
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x400f6450
 addq.l #8,%sp
 tst.l %d0
 bne.s cache_load_native
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 jsr sample_cache_acquire
 addq.l #8,%sp
 tst.l %d0
 beq.s cache_load_failed
cache_load_native:
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 jsr NATIVE_LOAD
 addq.l #8,%sp
 bra.s cache_load_done
cache_load_failed:
 moveq #0,%d0
cache_load_done:
 movem.l (%sp),%d2/%a2
 addq.l #8,%sp
 rts

/* Original project initializer may also receive non-cache destinations. */
sample_cache_blank:
 lea -8(%sp),%sp
 movem.l %d2/%a2,(%sp)
 move.l 12(%sp),%a2
 move.l %a2,-(%sp)
 jsr NATIVE_BLANK
 addq.l #4,%sp
 move.l %d0,%d2
 tst.b %d0
 beq.s cache_blank_done
 move.l %a2,-(%sp)
 jsr sample_cache_entry
 addq.l #4,%sp
 tst.l %d0
 beq.s cache_blank_done
 move.l %a2,-(%sp)
 move.l %d0,-(%sp)
 jsr sample_cache_reset
 addq.l #8,%sp
cache_blank_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2
 addq.l #8,%sp
 rts

/* MmcFs read(this,buffer,slot): original payload first, paired table second. */
sample_cache_read:
 lea -16(%sp),%sp
 movem.l %d2-%d3/%a2-%a3,(%sp)
 move.l 20(%sp),%d2
 move.l 24(%sp),%a2
 move.l 28(%sp),%d3
 move.l %d3,-(%sp)
 move.l %a2,-(%sp)
 move.l %d2,-(%sp)
 jsr 0x4012daa8
 lea 12(%sp),%sp
 tst.l %d0
 bne.w cache_read_done
 move.l %a2,-(%sp)
 jsr sample_cache_entry
 addq.l #4,%sp
 tst.l %d0
 beq.w cache_read_error
 move.l %d0,%a3
 clr.l 4(%a3)
 move.l %d3,(%a3)
 move.l 24(%a2),8(%a3)
 lea 16(%a3),%a0
 move.l %a0,-(%sp)
 move.l 24(%a2),-(%sp)
 move.l %d3,-(%sp)
 move.l %d2,-(%sp)
 jsr RECORD_READ
 lea 16(%sp),%sp
 tst.l %d0
 beq.s cache_read_ready
 cmpi.l #1,%d0
 bne.s cache_read_error
 /* Legacy/stale extension: empty. A matching damaged record is an error. */
 move.l #0x44543250,%d0
 cmp.l 16(%a3),%d0
 bne.s cache_read_empty
 move.l 24(%a2),%d0
 cmp.l 24(%a3),%d0
 beq.s cache_read_error
cache_read_empty:
 move.l %a2,-(%sp)
 move.l %a3,-(%sp)
 jsr sample_cache_reset
 addq.l #8,%sp
 bra.s cache_read_done
cache_read_ready:
 moveq #1,%d0
 move.l %d0,4(%a3)
 moveq #0,%d0
 bra.s cache_read_done
cache_read_error:
 moveq #3,%d0
cache_read_done:
 movem.l (%sp),%d2-%d3/%a2-%a3
 lea 16(%sp),%sp
 rts

/* MmcFs write(this,buffer,slot,ignore_protection,callback). */
sample_cache_write:
 lea -20(%sp),%sp
 movem.l %d2-%d4/%a2-%a3,(%sp)
 move.l 24(%sp),%d2
 move.l 28(%sp),%a2
 move.l 32(%sp),%d3
 move.l %a2,-(%sp)
 jsr sample_cache_entry
 addq.l #4,%sp
 tst.l %d0
 beq.w cache_write_error
 move.l %d0,%a3
 tst.l 4(%a3)
 beq.w cache_write_error
 cmp.l (%a3),%d3
 bne.w cache_write_error
 move.l 24(%a2),%d0
 cmp.l 8(%a3),%d0
 bne.w cache_write_error
 move.l 40(%sp),%a0
 move.l 36(%sp),%d4
 move.l %a0,-(%sp)
 move.l %d4,-(%sp)
 move.l %d3,-(%sp)
 move.l %a2,-(%sp)
 move.l %d2,-(%sp)
 jsr 0x4012ee34
 lea 20(%sp),%sp
 tst.l %d0
 bne.s cache_write_done
 lea 16(%a3),%a0
 move.l %a0,-(%sp)
 lea 528(%a3),%a0
 move.l %a0,-(%sp)
 move.l 8(%a3),-(%sp)
 move.l %d3,-(%sp)
 move.l %d2,-(%sp)
 jsr RECORD_WRITE
 lea 20(%sp),%sp
 tst.l %d0
 beq.s cache_write_done
cache_write_error:
 moveq #2,%d0 /* native write error; cache commit must not report success */
cache_write_done:
 movem.l (%sp),%d2-%d4/%a2-%a3
 lea 20(%sp),%sp
 rts
.balign 4
