/* Optional RCR1 record in DT2P header bytes20..37 (hex). Existing identity
 * layout/CRC stays unchanged. No allocation, media I/O or new lifecycle.
 * Native DT2 packed project bytesEC..FA and their exact restore clamps apply.
 */
.text
.global recorder_persist_prepare,recorder_persist_reset,recorder_persist_publish
.global recorder_persist_crc,recorder_persist_pack,recorder_persist_load

/* CRC32 of the16 packed bytes (15 native bytes + zero padding). */
recorder_persist_crc:
 move.l %d2,-(%sp)
 movea.l 8(%sp),%a0
 moveq #16,%d1
 moveq #-1,%d0
persist_crc_byte:
 mvz.b (%a0)+,%d2
 eor.l %d2,%d0
 moveq #8,%d2
persist_crc_bit:
 lsr.l #1,%d0
 bcc.s persist_crc_next
 eori.l #0xedb88320,%d0
persist_crc_next:
 subq.l #1,%d2
 bne.s persist_crc_bit
 subq.l #1,%d1
 bne.s persist_crc_byte
 not.l %d0
 move.l (%sp)+,%d2
 rts

/* (extension*, raw36*) -> exact donor serialization + local integrity tag. */
recorder_persist_pack:
 lea -12(%sp),%sp
 movem.l %a2-%a4,(%sp)
 movea.l 16(%sp),%a4
 movea.l 20(%sp),%a3
 suba.l #0x1ae,%a3
 lea -0xe8(%a4),%a2
 jsr recorder_persist_native_pack
 clr.b 19(%a4)
 pea 4(%a4)
 jsr recorder_persist_crc
 addq.l #4,%sp
 move.l %d0,20(%a4)
 move.l #0x52435231,(%a4)
 movem.l (%sp),%a2-%a4
 lea 12(%sp),%sp
 rts

/* (extension*) -> restore fixed live state; legacy/corrupt metadata defaults.
 * Sample identity validation remains independent from optional preferences.
 */
recorder_persist_load:
 lea -16(%sp),%sp
 movem.l %d2/%d4/%a2-%a3,(%sp)
 movea.l 20(%sp),%a3
 move.l #0x52435231,%d0
 cmp.l (%a3),%d0
 bne.s persist_load_default
 pea 4(%a3)
 jsr recorder_persist_crc
 addq.l #4,%sp
 cmp.l 20(%a3),%d0
 bne.s persist_load_default
 suba.l #0xe8,%a3
 movea.l #LIVE_STATE-0x1ae,%a2
 jsr recorder_persist_native_unpack
 bra.s persist_load_done
persist_load_default:
 pea 36
 pea recorder_persist_defaults
 pea LIVE_STATE
 jsr 0x40134490
 lea 12(%sp),%sp
persist_load_done:
 movem.l (%sp),%d2/%d4/%a2-%a3
 lea 16(%sp),%sp
 rts

/* Keep optional metadata when native prepare refreshes an in-place record.
 * Independent identity arrays retain the historical all-zero spare header.
 */
recorder_persist_prepare:
 lea -36(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 movea.l 40(%sp),%a2
 movea.l 48(%sp),%a3
 clr.l 12(%sp)
 clr.l 16(%sp)
 clr.l 20(%sp)
 clr.l 24(%sp)
 clr.l 28(%sp)
 clr.l 32(%sp)
 tst.l %a2
 beq.s persist_prepare_native
 lea 512(%a2),%a0
 cmpa.l %a0,%a3
 bne.s persist_prepare_native
 move.l 32(%a2),12(%sp)
 move.l 36(%a2),16(%sp)
 move.l 40(%a2),20(%sp)
 move.l 44(%a2),24(%sp)
 move.l 48(%a2),28(%sp)
 move.l 52(%a2),32(%sp)
persist_prepare_native:
 move.l %a3,-(%sp)
 move.l 48(%sp),-(%sp)
 move.l %a2,-(%sp)
 jsr ORIGINAL_PREPARE
 lea 12(%sp),%sp
 move.l %d0,%d2
 tst.l %d0
 bne.s persist_prepare_done
 move.l 12(%sp),32(%a2)
 move.l 16(%sp),36(%a2)
 move.l 20(%sp),40(%a2)
 move.l 24(%sp),44(%a2)
 move.l 28(%sp),48(%a2)
 move.l 32(%sp),52(%a2)
persist_prepare_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a3
 lea 36(%sp),%sp
 rts

/* Reusing/blanking a cache must never inherit its previous preferences. */
recorder_persist_reset:
 movea.l 4(%sp),%a0
 clr.l 48(%a0)
 clr.l 52(%a0)
 clr.l 56(%a0)
 clr.l 60(%a0)
 clr.l 64(%a0)
 clr.l 68(%a0)
 jmp ORIGINAL_RESET

/* In native project_publish just before ready=1: A2 dest, A3 source.
 * Preserve source prefs before exposing the completed companion to readers.
 */
recorder_persist_publish:
 lea -12(%sp),%sp
 movem.l %a2-%a4,(%sp)
 movea.l %a2,%a4
 tst.l %a3
 beq.s persist_publish_empty
 cmpa.l ACTIVE_STATE_PTR,%a3
 bne.s persist_publish_copy
 pea LIVE_STATE
 pea 48(%a4)
 jsr recorder_persist_pack
 addq.l #8,%sp
 bra.s persist_publish_restore
persist_publish_copy:
 move.l 48(%a3),48(%a4)
 move.l 52(%a3),52(%a4)
 move.l 56(%a3),56(%a4)
 move.l 60(%a3),60(%a4)
 move.l 64(%a3),64(%a4)
 move.l 68(%a3),68(%a4)
 bra.s persist_publish_restore
persist_publish_empty:
 pea recorder_persist_defaults
 pea 48(%a4)
 jsr recorder_persist_pack
 addq.l #8,%sp
persist_publish_restore:
 cmpa.l ACTIVE_STATE_PTR,%a4
 bne.s persist_publish_done
 pea 48(%a4)
 jsr recorder_persist_load
 addq.l #4,%sp
persist_publish_done:
 movem.l (%sp),%a2-%a4
 lea 12(%sp),%sp
 moveq #1,%d0
 move.l %d0,4(%a2)
 rts
.balign 4
