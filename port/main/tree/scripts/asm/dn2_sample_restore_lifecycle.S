/* DN2 project boundary glue around the original DT2 restoration worker.
 * A native recursive mutex serializes mutation with restoration. Set cancel
 * before taking it so an in-flight worker stops at its next sample boundary.
 * Queued jobs retain their epoch until drained; UI polling never duplicates
 * them or reuses their single proxy while they are pending.
 */
.text
.global sample_restore_poll,sample_restore_job,sample_restore_deserialize
.global sample_restore_clear,sample_restore_lock,sample_restore_epoch
.global sample_restore_done,sample_restore_pending,sample_restore_requested

sample_restore_poll:
 jsr FS_STARTUP
 move.l FS_STATUS,%d0
 cmpi.l #2,%d0
 bne.w poll_return
 pea sample_restore_lock
 jsr 0x4000169e
 addq.l #4,%sp
 tst.b %d0
 beq.w poll_return
 tst.l sample_restore_pending
 bne.w poll_unlock
 move.l sample_restore_epoch,%d0
 cmp.l sample_restore_done,%d0
 beq.w poll_unlock
 move.l 0x446478d0,%d0
 beq.w poll_unlock
 addi.l #0x30,%d0
 move.l %d0,-(%sp)
 jsr SETTINGS_RAW
 addq.l #4,%sp
 tst.l %d0
 beq.s poll_unlock
 move.l 0x446478d0,%d0
 addi.l #0x30,%d0
 move.l %d0,-(%sp)
 jsr PROXY_INIT
 addq.l #4,%sp
 tst.l %d0
 beq.s poll_unlock
 move.l sample_restore_epoch,%d1
 move.l %d1,sample_restore_requested
 moveq #1,%d1
 move.l %d1,sample_restore_pending
 pea 1.w
 move.l %d0,-(%sp)
 jsr RESTORE
 addq.l #8,%sp
poll_unlock:
 pea sample_restore_lock
 jsr 0x4000172a
 addq.l #4,%sp
poll_return:
 rts

/* Native std::function invocation passes the original capture object. */
sample_restore_job:
 move.l %a2,-(%sp)
 move.l 8(%sp),%a2
 pea sample_restore_lock
 jsr 0x40001608
 addq.l #4,%sp
 move.l sample_restore_requested,%d0
 cmp.l sample_restore_epoch,%d0
 bne.s job_done
 move.l #PROXY,-(%sp)
 jsr PROXY_RAW
 addq.l #4,%sp
 tst.l %d0
 beq.s job_done
 moveq #2,%d0
 move.l %d0,sample_restore_pending
 move.l %a2,-(%sp)
 jsr ORIGINAL_JOB
 addq.l #4,%sp
 move.l sample_restore_requested,%d0
 move.l %d0,sample_restore_done
job_done:
 clr.l sample_restore_pending
 pea sample_restore_lock
 jsr 0x4000172a
 addq.l #4,%sp
 moveq #1,%d0
 move.l (%sp)+,%a2
 rts

/* Called only when raw destination is the live project (or boot buffer).
 * Recursive locking also handles raw initialization inside deserialization.
 */
restore_mutation_begin:
 moveq #1,%d0
 move.b %d0,PROXY+0xa8
 pea sample_restore_lock
 jsr 0x40001608
 addq.l #4,%sp
 addq.l #1,sample_restore_epoch
 rts
restore_mutation_end:
 pea sample_restore_lock
 jsr 0x4000172a
 addq.l #4,%sp
 rts

/* (raw destination, serialized source, callback) -> native bool. */
sample_restore_deserialize:
 move.l 4(%sp),%d1
 bsr.w restore_is_live_raw
 tst.l %d0
 beq.s deserialize_direct
 lea -8(%sp),%sp
 movem.l %d2/%a2,(%sp)
 bsr.w restore_mutation_begin
 move.l 20(%sp),-(%sp)
 move.l 20(%sp),-(%sp)
 move.l 20(%sp),-(%sp)
 jsr ORIGINAL_DESERIALIZE
 lea 12(%sp),%sp
 move.l %d0,%d2
 bsr.w restore_mutation_end
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2
 addq.l #8,%sp
 rts
deserialize_direct:
 jmp ORIGINAL_DESERIALIZE

/* (raw destination) -> preserve native void return register. */
sample_restore_clear:
 move.l 4(%sp),%d1
 bsr.w restore_is_live_raw
 tst.l %d0
 beq.s clear_direct
 move.l %d2,-(%sp)
 bsr.w restore_mutation_begin
 move.l 8(%sp),-(%sp)
 jsr ORIGINAL_CLEAR
 addq.l #4,%sp
 move.l %d0,%d2
 bsr.w restore_mutation_end
 move.l %d2,%d0
 move.l (%sp)+,%d2
 rts
clear_direct:
 jmp ORIGINAL_CLEAR

restore_is_live_raw:
 move.l 0x446478d0,%d0
 beq.s raw_boot
 move.l %d0,%a0
 cmp.l 16(%a0),%d1
 seq %d0
 andi.l #1,%d0
 rts
raw_boot:
 cmpi.l #0x41218970,%d1
 seq %d0
 andi.l #1,%d0
 rts

.balign 4
sample_restore_lock: .long 0,0,0,0
sample_restore_epoch: .long 1
sample_restore_done: .long 0
sample_restore_pending: .long 0
sample_restore_requested: .long 0
