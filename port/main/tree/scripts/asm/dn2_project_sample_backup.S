/* Native working-project backup slots40000/48000, legacy lengthC4B114.
 * DT2 record at+C4B200 fits within the existing final32KiB power-off block.
 * All allocation happens during startup, never in the power-off writer.
 */
.text
.global sample_backup_restore,sample_backup_write,sample_backup_chunk
.global sample_backup_tail,sample_backup_deserialize,sample_backup_serialize
sample_backup_restore:
 lea -16(%sp),%sp
 movem.l %d2/%a2-%a4,(%sp)
 jsr NATIVE_RESTORE
 move.l %d0,%d2
 jsr PROJECT_STATE
 move.l %d0,%a2
 tst.l %d0
 beq.w backup_restore_done
 lea 0x4210(%a2),%a3
 clr.l 4(%a2)
 clr.l 4(%a3)
 move.l BACKUP_CHUNK,%d0
 bne.s backup_restore_read
 move.l #0x8000,-(%sp)
 jsr 0x40120264
 addq.l #4,%sp
 move.l %d0,BACKUP_CHUNK
backup_restore_read:
 move.l 0x40295b0c,%d0
 cmpi.l #1,%d0
 bhi.w backup_restore_done
 lsl.l #2,%d0
 move.l #0x401ff6f8,%a0
 move.l (%a0,%d0.l),%d0
 addi.l #0x6259,%d0
 lea 16(%a3),%a4
 move.l %a4,-(%sp)
 move.l #0x4200,-(%sp)
 move.l %d0,-(%sp)
 jsr 0x4012c59a
 lea 12(%sp),%sp
 tst.l %d0
 bmi.s backup_restore_done
 move.l 0x405cd984,-(%sp)
 move.l %a4,-(%sp)
 jsr RECORD_VALIDATE
 addq.l #8,%sp
 tst.l %d0
 beq.s backup_restore_ready
 move.l #0x44543250,%d0
 cmp.l (%a4),%d0
 beq.s backup_restore_done
 /* No extension marker: legacy backup, with no sampler identity table. */
 move.l #128,-(%sp)
 move.l 0x405cd984,-(%sp)
 move.l #0x405cd96c,-(%sp)
 clr.l -(%sp)
 move.l %a3,-(%sp)
 jsr PROJECT_PUBLISH
 lea 20(%sp),%sp
 bra.s backup_restore_done
backup_restore_ready:
 move.l #128,%d0
 move.l %d0,(%a3)
 move.l 0x405cd984,%d0
 move.l %d0,8(%a3)
 move.l #0x405cd96c,%d0
 move.l %d0,12(%a3)
 moveq #1,%d0
 move.l %d0,4(%a3)
backup_restore_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a4
 lea 16(%sp),%sp
 rts

/* Produce native last block + identity record in preallocated scratch.
 * Called with no args; returns buffer or0. No allocation/CRC/mutex/I/O here.
 */
sample_backup_tail:
 lea -8(%sp),%sp
 movem.l %a2-%a3,(%sp)
 move.l BACKUP_CHUNK,%a2
 tst.l %a2
 beq.w backup_tail_done
 move.l #0x8000,-(%sp)
 clr.l -(%sp)
 move.l %a2,-(%sp)
 jsr 0x401344d8
 lea 12(%sp),%sp
 move.l #0x3114,-(%sp)
 move.l #0x4121585c,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x40134490
 lea 12(%sp),%sp
 move.l ACTIVE_STATE_PTR,%d0
 beq.s backup_tail_invalid
 move.l %d0,%a3
 lea 0x4210(%a3),%a3
 moveq #1,%d0
 cmp.l 4(%a3),%d0
 bne.s backup_tail_invalid
 move.l 0x405cd984,%d0
 cmp.l 8(%a3),%d0
 bne.s backup_tail_invalid
 move.l #0x4200,-(%sp)
 lea 16(%a3),%a0
 move.l %a0,-(%sp)
 lea 0x3200(%a2),%a0
 move.l %a0,-(%sp)
 jsr 0x40134490
 lea 12(%sp),%sp
 bra.s backup_tail_done
backup_tail_invalid:
 /* Explicit damaged-extension marker prevents stale/missing state from being
  * silently mistaken for a legacy empty pool on the next boot. */
 move.l #0x44543250,%d0
 move.l %d0,0x3200(%a2)
 moveq #2,%d0
 move.l %d0,0x3204(%a2)
 move.l 0x405cd984,%d0
 move.l %d0,0x3208(%a2)
backup_tail_done:
 move.l %a2,%d0
 movem.l (%sp),%a2-%a3
 addq.l #8,%sp
 rts

/* Native interrupt writer(LBA,source) always writes32KiB. */
sample_backup_chunk:
 move.l 8(%sp),%d0
 cmpi.l #0x4121585c,%d0
 bne.s backup_chunk_native
 move.l %a2,-(%sp)
 move.l 8(%sp),%a2
 jsr sample_backup_tail
 tst.l %d0
 beq.s backup_chunk_missing
 move.l %d0,-(%sp)
 move.l %a2,-(%sp)
 jsr NATIVE_CHUNK
 addq.l #8,%sp
 move.l (%sp)+,%a2
 rts
backup_chunk_missing:
 move.l (%sp)+,%a2
backup_chunk_native:
 jmp NATIVE_CHUNK

/* Normal writer(LBA,bytes,source), VOID. Append record to full snapshots. */
sample_backup_write:
 lea -16(%sp),%sp
 movem.l %d2-%d3/%a2-%a3,(%sp)
 move.l 20(%sp),%d3
 move.l 24(%sp),%a2
 move.l 28(%sp),%a3
 /* Mark an overwritten extension incomplete before writing the new payload. */
 cmpa.l #0xc4b114,%a2
 bne.s backup_write_native
 cmpa.l #0x405cd85c,%a3
 bne.s backup_write_native
 cmpi.l #0x40000,%d3
 beq.s backup_write_invalidate
 cmpi.l #0x48000,%d3
 bne.s backup_write_native
backup_write_invalidate:
 jsr sample_backup_tail
 tst.l %d0
 beq.s backup_write_native
 move.l %d0,%a0
 moveq #2,%d0
 move.l %d0,0x3204(%a0)
 lea 0x3200(%a0),%a0
 move.l %a0,-(%sp)
 move.l #512,-(%sp)
 move.l %d3,%d0
 addi.l #0x6259,%d0
 move.l %d0,-(%sp)
 jsr 0x4012c780
 lea 12(%sp),%sp
backup_write_native:
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 move.l %d3,-(%sp)
 jsr NATIVE_WRITE
 lea 12(%sp),%sp
 move.l %d0,%d2
 cmpa.l #0xc4b114,%a2
 bne.s backup_write_done
 cmpa.l #0x405cd85c,%a3
 bne.s backup_write_done
 cmpi.l #0x40000,%d3
 beq.s backup_write_record
 cmpi.l #0x48000,%d3
 bne.s backup_write_done
backup_write_record:
 jsr sample_backup_tail
 tst.l %d0
 beq.s backup_write_done
 addi.l #0x3200,%d0
 addi.l #0x6259,%d3
 move.l %d0,-(%sp)
 move.l #0x4200,-(%sp)
 move.l %d3,-(%sp)
 jsr 0x4012c780
 lea 12(%sp),%sp
backup_write_done:
 move.l %d2,%d0
 movem.l (%sp),%d2-%d3/%a2-%a3
 lea 16(%sp),%sp
 rts

/* Bootstrap conversion precedes singleton construction; keep native bool
 * even when companion is unavailable, preserving the native project itself.
 */
sample_backup_deserialize:
 tst.l 0x446478d0
 bne.w backup_deserialize_delegate
 move.l 4(%sp),%d0
 cmpi.l #0x41218970,%d0
 bne.w backup_deserialize_delegate
 move.l 8(%sp),%d0
 cmpi.l #0x405cd96c,%d0
 bne.w backup_deserialize_delegate
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 jsr NATIVE_DESERIALIZE
 lea 12(%sp),%sp
 move.l %d0,%d2
 jsr PROJECT_STATE
 move.l %d0,%a2
 tst.l %d0
 beq.s backup_deserialize_done
 clr.l 4(%a2)
 tst.b %d2
 beq.s backup_deserialize_done
 lea 0x4210(%a2),%a3
 moveq #1,%d0
 cmp.l 4(%a3),%d0
 bne.s backup_deserialize_done
 move.l #128,-(%sp)
 move.l 0x41218978,-(%sp)
 move.l #0x41218970,-(%sp)
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 jsr PROJECT_PUBLISH
 lea 20(%sp),%sp
backup_deserialize_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts
backup_deserialize_delegate:
 jmp ACTIVE_DESERIALIZE

sample_backup_serialize:
 tst.l 0x446478d0
 bne.w backup_serialize_delegate
 move.l 4(%sp),%d0
 cmpi.l #0x405cd96c,%d0
 bne.w backup_serialize_delegate
 move.l 8(%sp),%d0
 cmpi.l #0x41218970,%d0
 bne.w backup_serialize_delegate
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 move.l 32(%sp),-(%sp)
 move.l 32(%sp),-(%sp)
 move.l 32(%sp),-(%sp)
 move.l 32(%sp),-(%sp)
 move.l 32(%sp),-(%sp)
 jsr NATIVE_SERIALIZE
 lea 20(%sp),%sp
 move.l %d0,%d2
 move.l ACTIVE_STATE_PTR,%d0
 beq.s backup_serialize_done
 move.l %d0,%a2
 lea 0x4210(%a2),%a3
 clr.l 4(%a3)
 tst.b %d2
 beq.s backup_serialize_done
 moveq #1,%d0
 cmp.l 4(%a2),%d0
 bne.s backup_serialize_done
 move.l #0x41218970,%d0
 cmp.l 12(%a2),%d0
 bne.s backup_serialize_done
 move.l #128,-(%sp)
 move.l 0x405cd984,-(%sp)
 move.l #0x405cd96c,-(%sp)
 move.l %a2,-(%sp)
 move.l %a3,-(%sp)
 jsr PROJECT_PUBLISH
 lea 20(%sp),%sp
backup_serialize_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts
backup_serialize_delegate:
 jmp ACTIVE_SERIALIZE
