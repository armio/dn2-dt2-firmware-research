/* DN2 adapter for persistent DT2 sample identities, OS1.11 only.
 * A project uses C4B004 bytes of its 1000000-byte MmcFs slot. Our record
 * occupies C4B200..C4F400, on sector boundaries. Native payload is untouched.
 * Record: magic DT2P, version1, project UID, identity bytes4000, CRC32;
 * 512-byte header, then the unchanged 1024*16 DT2 identities.
 * Return:0 success,1 missing/stale/corrupt,2 invalid argument,3 I/O error.
 * Caller owns the4200-byte work record and publishes it only on success.
 */
.text
.global sample_record_crc,sample_record_prepare,sample_record_validate
.global sample_record_read,sample_record_write
sample_record_crc:
 move.l %d2,-(%sp)
 move.l 8(%sp),%a0
 move.l #16384,%d1
 moveq #-1,%d0
crc_byte:
 mvz.b (%a0)+,%d2
 eor.l %d2,%d0
 moveq #8,%d2
crc_bit:
 lsr.l #1,%d0
 bcc.s crc_next
 eori.l #0xedb88320,%d0
crc_next:
 subq.l #1,%d2
 bne.s crc_bit
 subq.l #1,%d1
 bne.s crc_byte
 not.l %d0
 move.l (%sp)+,%d2
 rts

/* (record*, project UID, identities*) */
sample_record_prepare:
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 move.l 16(%sp),%a2
 move.l 20(%sp),%d2
 move.l 24(%sp),%a3
 tst.l %a2
 beq.w record_prepare_bad
 tst.l %a3
 beq.w record_prepare_bad
 /* Clear header only, then copy the unchanged identity bytes. */
 move.l #512,-(%sp)
 clr.l -(%sp)
 move.l %a2,-(%sp)
 jsr 0x401344d8
 lea 12(%sp),%sp
 move.l #0x44543250,(%a2)
 moveq #1,%d0
 move.l %d0,4(%a2)
 move.l %d2,8(%a2)
 move.l #16384,%d0
 move.l %d0,12(%a2)
 move.l #16384,-(%sp)
 move.l %a3,-(%sp)
 lea 512(%a2),%a3
 move.l %a3,-(%sp)
 jsr 0x40134490
 lea 12(%sp),%sp
 move.l %a3,-(%sp)
 jsr sample_record_crc
 addq.l #4,%sp
 move.l %d0,16(%a2)
 moveq #0,%d0
 bra.s record_prepare_done
record_prepare_bad:
 moveq #2,%d0
record_prepare_done:
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts

/* (record*, expected project UID) */
sample_record_validate:
 move.l %a2,-(%sp)
 move.l 8(%sp),%a2
 tst.l %a2
 beq.s record_validate_bad
 move.l #0x44543250,%d0
 cmp.l (%a2),%d0
 bne.s record_validate_missing
 moveq #1,%d0
 cmp.l 4(%a2),%d0
 bne.s record_validate_missing
 move.l 12(%sp),%d0
 cmp.l 8(%a2),%d0
 bne.s record_validate_missing
 move.l #16384,%d0
 cmp.l 12(%a2),%d0
 bne.s record_validate_missing
 lea 512(%a2),%a0
 move.l %a0,-(%sp)
 jsr sample_record_crc
 addq.l #4,%sp
 cmp.l 16(%a2),%d0
 bne.s record_validate_missing
 moveq #0,%d0
 bra.s record_validate_done
record_validate_missing:
 moveq #1,%d0
 bra.s record_validate_done
record_validate_bad:
 moveq #2,%d0
record_validate_done:
 move.l (%sp)+,%a2
 rts

/* (MmcFs*, slot0..128, expected UID, record*) */
sample_record_read:
 lea -16(%sp),%sp
 movem.l %d2-%d3/%a2-%a3,(%sp)
 move.l 20(%sp),%a2
 move.l 24(%sp),%d2
 move.l 28(%sp),%d3
 move.l 32(%sp),%a3
 tst.l %a2
 beq.s record_read_bad
 tst.l %a3
 beq.s record_read_bad
 cmpi.l #128,%d2
 bhi.s record_read_bad
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x4012d7c2
 addq.l #8,%sp
 addi.l #0x6259,%d0 /* C4B200/512 */
 /* readBytes(this,LBA,bytes,destination,unused progress callback) */
 clr.l -(%sp)
 move.l %a3,-(%sp)
 move.l #0x4200,-(%sp)
 move.l %d0,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x4012d0b4
 lea 20(%sp),%sp
 tst.l %d0
 bne.s record_read_io
 move.l %d3,-(%sp)
 move.l %a3,-(%sp)
 jsr sample_record_validate
 addq.l #8,%sp
 bra.s record_read_done
record_read_io:
 moveq #3,%d0
 bra.s record_read_done
record_read_bad:
 moveq #2,%d0
record_read_done:
 movem.l (%sp),%d2-%d3/%a2-%a3
 lea 16(%sp),%sp
 rts

/* (MmcFs*, slot0..128, project UID, identities*, work record*) */
sample_record_write:
 lea -36(%sp),%sp
 movem.l %d2-%d3/%a2-%a3,(%sp)
 move.l 40(%sp),%a2
 move.l 44(%sp),%d2
 move.l 56(%sp),%a3
 tst.l %a2
 beq.w record_write_bad
 tst.l %a3
 beq.w record_write_bad
 cmpi.l #128,%d2
 bhi.w record_write_bad
 move.l 52(%sp),%a0
 move.l 48(%sp),%d3
 move.l %a0,-(%sp)
 move.l %d3,-(%sp)
 move.l %a3,-(%sp)
 jsr sample_record_prepare
 lea 12(%sp),%sp
 tst.l %d0
 bne.s record_write_done
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x4012d7c2
 addq.l #8,%sp
 addi.l #0x6259,%d0
 /* Empty std::function progress callback at local+16. */
 clr.l 16(%sp)
 clr.l 20(%sp)
 clr.l 24(%sp)
 clr.l 28(%sp)
 lea 16(%sp),%a0
 /* writeBytes(this,LBA,bytes,source,&callback,allow_sector_zero=false) */
 clr.l -(%sp)
 move.l %a0,-(%sp)
 move.l %a3,-(%sp)
 move.l #0x4200,-(%sp)
 move.l %d0,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x4012e586
 lea 24(%sp),%sp
 tst.l %d0
 beq.s record_write_done
 moveq #3,%d0
 bra.s record_write_done
record_write_bad:
 moveq #2,%d0
record_write_done:
 movem.l (%sp),%d2-%d3/%a2-%a3
 lea 36(%sp),%sp
 rts
.balign 4
