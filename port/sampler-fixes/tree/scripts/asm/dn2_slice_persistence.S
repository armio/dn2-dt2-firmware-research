/* SLICE grids are immutable ekFS objects; native Sounds keep a 20-byte key.
 * File I/O runs only from native serialization/deserialization or UI poll.
 * Never called by SHARC rendering or the ColdFire voice-frame adapter. */
.text
.global slice_storage_key,slice_storage_prepare,slice_storage_restore
.global slice_storage_save,slice_storage_load,slice_storage_poll,slice_storage_clear
.global slice_storage_status,slice_storage_failures

/* (map772*, key16*): four seeded FNV-1a32 digests, exact bytes, big endian. */
slice_storage_key:
 lea -20(%sp),%sp
 movem.l %d2-%d4/%a2-%a3,(%sp)
 movea.l 24(%sp),%a2
 movea.l 28(%sp),%a3
 lea hash_seeds,%a1
 moveq #4,%d4
key_word:
 movea.l %a2,%a0
 move.l (%a1)+,%d0
 move.l #772,%d2
 move.l #0x01000193,%d3
key_byte:
 mvz.b (%a0)+,%d1
 eor.l %d1,%d0
 mulu.l %d3,%d0
 subq.l #1,%d2
 bne.s key_byte
 move.l %d0,(%a3)+
 subq.l #1,%d4
 bne.s key_word
 movem.l (%sp),%d2-%d4/%a2-%a3
 lea 20(%sp),%sp
 rts

/* (a*,b*,bytes), boolean exact equality. */
equal:
 movea.l 4(%sp),%a0
 movea.l 8(%sp),%a1
 move.l 12(%sp),%d0
equal_byte:
 move.b (%a0)+,%d1
 cmp.b (%a1)+,%d1
 bne.s equal_no
 subq.l #1,%d0
 bne.s equal_byte
 moveq #1,%d0
 rts
equal_no:
 moveq #0,%d0
 rts

/* io(sound,write): heap 864 = blob776,key16,handle16,path44,scratch12.
 * Read path is immutable; write existing paths only after exact comparison.
 * A newly written file must close, reopen and read back before publishing. */
storage_io:
 lea -32(%sp),%sp
 movem.l %d2-%d5/%a2-%a5,(%sp)
 movea.l 36(%sp),%a2
 move.l 40(%sp),%d5
 moveq #0,%d4
 moveq #6,%d3
 /* No allocation or file I/O in an interrupt/masked context. */
 move.w %sr,%d0
 andi.l #0x700,%d0
 bne.w io_deferred_unallocated
 pea 864.w
 jsr 0x40120264
 addq.l #4,%sp
 tst.l %d0
 beq.w io_done
 movea.l %d0,%a3
 lea 776(%a3),%a4
 lea 792(%a3),%a5
 tst.l %d5
 beq.s io_load_key
 move.l %a4,-(%sp)
 pea 375(%a2)
 bsr.w slice_storage_key
 addq.l #8,%sp
 bra.s io_key_ready
io_load_key:
 pea 16.w
 pea 104(%a2)
 move.l %a4,-(%sp)
 jsr 0x40134490
 lea 12(%sp),%sp
io_key_ready:
 tst.l FS_READY
 beq.w io_deferred
 /* '/.slc_' + 32 lowercase hexadecimal characters, NUL. */
 lea 808(%a3),%a0
 move.l #0x2f2e736c,(%a0)+
 move.w #0x635f,(%a0)+
 movea.l %a4,%a1
 moveq #16,%d2
path_byte:
 mvz.b (%a1)+,%d0
 move.l %d0,%d1
 lsr.l #4,%d0
 andi.l #15,%d1
 cmpi.l #9,%d0
 bls.s path_hi
 addq.l #7,%d0
path_hi:
 addi.l #48,%d0
 move.b %d0,(%a0)+
 cmpi.l #9,%d1
 bls.s path_lo
 addq.l #7,%d1
path_lo:
 addi.l #48,%d1
 move.b %d1,(%a0)+
 subq.l #1,%d2
 bne.s path_byte
 clr.b (%a0)
 moveq #0,%d2
io_read:
 move.l %a5,-(%sp)
 pea mode_r
 pea 808(%a3)
 jsr FS_OPEN
 lea 12(%sp),%sp
 tst.l %d0
 bne.w io_missing
 move.l %a5,-(%sp)
 pea 776.w
 move.l %a3,-(%sp)
 jsr FS_READ
 lea 12(%sp),%sp
 move.l %d0,%d4
 /* Exact length: one byte beyond the blob must be EOF. */
 move.l %a5,-(%sp)
 pea 1.w
 pea 856(%a3)
 jsr FS_READ
 lea 12(%sp),%sp
 move.l %d0,852(%a3)
 move.l %a5,-(%sp)
 jsr FS_CLOSE
 addq.l #4,%sp
 tst.l %d0
 bne.w io_error
 cmpi.l #776,%d4
 bne.w io_invalid
 tst.l 852(%a3)
 bne.w io_invalid
 move.l (%a3),%d0
 beq.w io_invalid
 cmpi.l #64,%d0
 bhi.w io_invalid
 /* Hash read map separately: do not overwrite the expected key. */
 lea -16(%sp),%sp
 move.l %sp,%a0
 move.l %a0,-(%sp)
 move.l %a3,-(%sp)
 bsr.w slice_storage_key
 addq.l #8,%sp
 move.l %sp,%a0
 move.l (%a0),%d0
 cmp.l 772(%a3),%d0
 bne.s io_bad_hash
 pea 16.w
 move.l %a4,-(%sp)
 move.l %a0,-(%sp)
 bsr.w equal
 lea 12(%sp),%sp
 tst.l %d0
 beq.s io_bad_hash
 lea 16(%sp),%sp
 tst.l %d5
 beq.w io_publish_map
 pea 772.w
 pea 375(%a2)
 move.l %a3,-(%sp)
 bsr.w equal
 lea 12(%sp),%sp
 tst.l %d0
 beq.w io_collision
 moveq #1,%d3
 bra.w io_publish_key
io_bad_hash:
 lea 16(%sp),%sp
 bra.w io_invalid
io_missing:
 tst.l %d5
 beq.w io_invalid
 tst.l %d2
 bne.w io_error
 /* A failed read open alone is not proof that a path is absent. Native
  * resolver0x19 proves a missing final component with a valid parent. */
 clr.l -(%sp)
 clr.l -(%sp)
 pea 860(%a3)
 pea 856(%a3)
 pea 808(%a3)
 jsr FS_RESOLVE
 lea 20(%sp),%sp
 cmpi.l #0x19,%d0
 bne.w io_error
 moveq #1,%d2
 pea 772.w
 pea 375(%a2)
 move.l %a3,-(%sp)
 jsr 0x40134490
 lea 12(%sp),%sp
 move.l (%a4),772(%a3)
 move.l %a5,-(%sp)
 pea mode_w
 pea 808(%a3)
 jsr FS_OPEN
 lea 12(%sp),%sp
 tst.l %d0
 bne.w io_error
 move.l %a5,-(%sp)
 pea 776.w
 move.l %a3,-(%sp)
 jsr FS_WRITE
 lea 12(%sp),%sp
 move.l %d0,%d4
 move.l %a5,-(%sp)
 jsr FS_CLOSE
 addq.l #4,%sp
 tst.l %d0
 bne.s io_error
 cmpi.l #776,%d4
 bne.s io_error
 bra.w io_read
io_publish_map:
 moveq #2,%d3
io_copy_map:
 /* Publish count last, after the complete validated marker array. */
 pea 768.w
 pea 4(%a3)
 pea 379(%a2)
 jsr 0x40134490
 lea 12(%sp),%sp
 move.l (%a3),375(%a2)
 clr.l 1147(%a2)
 moveq #1,%d4
 bra.s io_free
io_publish_key:
 pea 16.w
 move.l %a4,-(%sp)
 pea 104(%a2)
 jsr 0x40134490
 lea 12(%sp),%sp
 move.l #0x534c4631,100(%a2)
 moveq #1,%d4
 bra.s io_free
io_collision:
 moveq #7,%d3
 bra.s io_fail
io_invalid:
 moveq #5,%d3
 bra.s io_fail
io_error:
 moveq #6,%d3
io_fail:
 addq.l #1,slice_storage_failures
 tst.l %d5
 bne.s io_failed_save
 moveq #1,%d0
 move.l %d0,1147(%a2)
 bra.s io_failed
io_failed_save:
 /* Keep a prior persisted descriptor. With no prior key, write the failed
  * key so ignored native failure returns still fail closed on recall. */
 cmpi.l #0x534c4631,100(%a2)
 beq.s io_failed
 pea 16.w
 move.l %a4,-(%sp)
 pea 104(%a2)
 jsr 0x40134490
 lea 12(%sp),%sp
 move.l #0x534c4631,100(%a2)
io_failed:
 moveq #0,%d4
 bra.s io_free
io_deferred:
 moveq #4,%d3
 moveq #0,%d4
io_free:
 move.l %a3,-(%sp)
 jsr 0x40120270
 addq.l #4,%sp
 bra.s io_done
io_deferred_unallocated:
 moveq #4,%d3
io_done:
 move.l %d3,slice_storage_status
 move.l %d4,%d0
 movem.l (%sp),%d2-%d5/%a2-%a5
 lea 32(%sp),%sp
 rts

slice_storage_prepare:
 movea.l 4(%sp),%a0
 tst.l %a0
 beq.w prepare_native
 mvz.b 222(%a0),%d0
 cmpi.l #10,%d0
 bne.w prepare_native
 move.l 375(%a0),%d0
 beq.w prepare_empty
 cmpi.l #64,%d0
 bhi.w prepare_invalid
 /* Preserve a prior valid key until successful immutable-file readback. */
 move.l 100(%a0),%d0
 cmpi.l #0x534c4631,%d0
 beq.s prepare_write
 pea 104(%a0)
 pea 375(%a0)
 bsr.w slice_storage_key
 addq.l #8,%sp
 movea.l 4(%sp),%a0
 move.l #0x534c4631,%d0
 move.l %d0,100(%a0)
prepare_write:
 pea 1.w
 move.l 8(%sp),-(%sp)
 bsr.w storage_io
 addq.l #8,%sp
 rts
prepare_empty:
 /* An unresolved loaded key must survive save before filesystem mounting.
  * Explicit native slice clear invalidates its key in slice_storage_clear. */
 move.l 100(%a0),%d0
 cmpi.l #0x534c4631,%d0
 beq.s prepare_native
 clr.l 100(%a0)
 clr.l 104(%a0)
 clr.l 108(%a0)
 clr.l 112(%a0)
 clr.l 116(%a0)
 clr.l 1147(%a0)
prepare_native:
 moveq #1,%d0
 rts
prepare_invalid:
 moveq #5,%d0
 move.l %d0,slice_storage_status
 addq.l #1,slice_storage_failures
 moveq #0,%d0
 rts

slice_storage_restore:
 movea.l 4(%sp),%a0
 tst.l %a0
 beq.s restore_done
 mvz.b 222(%a0),%d0
 cmpi.l #10,%d0
 bne.s restore_done
 move.l 100(%a0),%d0
 cmpi.l #0x534c4631,%d0
 bne.s restore_done
 tst.l 375(%a0)
 bne.s restore_done
 tst.l 1147(%a0)
 bne.s restore_done
 clr.l -(%sp)
 move.l %a0,-(%sp)
 bsr.w storage_io
 addq.l #8,%sp
restore_done:
 rts

slice_storage_save:
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 movea.l 16(%sp),%a2
 movea.l 20(%sp),%a3
 move.l %a3,-(%sp)
 bsr.w slice_storage_prepare
 addq.l #4,%sp
 move.l %d0,%d2
 move.l 24(%sp),-(%sp)
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 bsr.w native_save
 lea 12(%sp),%sp
 and.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts
native_save:
 lea -36(%sp),%sp
 movem.l %d2-%d5/%a2-%a6,(%sp)
 jmp 0x400dd6ae

slice_storage_load:
 lea -8(%sp),%sp
 movem.l %d2/%a2,(%sp)
 movea.l 12(%sp),%a2
 move.l 16(%sp),-(%sp)
 move.l %a2,-(%sp)
 bsr.w native_load
 addq.l #8,%sp
 move.l %d0,%d2
 tst.b %d0
 beq.s load_done
 mvz.b 222(%a2),%d0
 cmpi.l #10,%d0
 bne.s load_done
 pea 772.w
 clr.l -(%sp)
 pea 375(%a2)
 jsr 0x401344d8
 lea 12(%sp),%sp
 clr.l 1147(%a2)
 move.l %a2,-(%sp)
 bsr.w slice_storage_restore
 addq.l #4,%sp
load_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2
 addq.l #8,%sp
 rts
native_load:
 lea -32(%sp),%sp
 movem.l %d2-%d4/%a2-%a6,(%sp)
 jmp 0x400dd1f2

/* Replaces the original final count clear and register restore. */
slice_storage_clear:
 move.l %d0,-(%sp)
 mvz.b 222(%a0),%d0
 cmpi.l #10,%d0
 bne.s clear_count
 clr.l 100(%a0)
 clr.l 104(%a0)
 clr.l 108(%a0)
 clr.l 112(%a0)
 clr.l 116(%a0)
 clr.l 1147(%a0)
clear_count:
 move.l (%sp)+,%d0
 clr.l 375(%a0)
 movem.l (%sp),%d2-%d3/%a2
 jmp CLEAR_RETURN

/* Established UI poll after filesystem startup and existing delegates. */
slice_storage_poll:
 jsr POLL_DELEGATE
 lea -28(%sp),%sp
 movem.l %d0-%d2/%a0-%a3,(%sp)
 tst.l FS_READY
 beq.s poll_done
 movea.l 0x446478d0,%a0
 tst.l %a0
 beq.s poll_done
 lea 0x160(%a0),%a2
 moveq #16,%d2
poll_track:
 movea.l 0x10(%a2),%a3
 tst.l %a3
 beq.s poll_next
 tst.l 375(%a3)
 bne.s poll_next
 move.l %a3,-(%sp)
 bsr.w slice_storage_restore
 addq.l #4,%sp
 tst.l 375(%a3)
 beq.s poll_next
 /* Native SliceInfo refresh after deferred restore, without marking edit. */
 lea -8(%sp),%sp
 move.l #SLICE_INFO,%d0
 move.l %d0,(%sp)
 clr.l 4(%sp)
 move.l %sp,%a0
 move.l %a0,-(%sp)
 move.l %a2,-(%sp)
 movea.l (%a2),%a0
 movea.l 16(%a0),%a0
 jsr (%a0)
 lea 16(%sp),%sp
poll_next:
 lea 0x3c0(%a2),%a2
 subq.l #1,%d2
 bne.s poll_track
poll_done:
 movem.l (%sp),%d0-%d2/%a0-%a3
 lea 28(%sp),%sp
 rts
.balign 4
hash_seeds: .long 0x811c9dc5,0x9e3779b9,0x85ebca6b,0xc2b2ae35
mode_r: .asciz "r"
mode_w: .asciz "w"
.balign 4
slice_storage_status: .long 0
slice_storage_failures: .long 0
