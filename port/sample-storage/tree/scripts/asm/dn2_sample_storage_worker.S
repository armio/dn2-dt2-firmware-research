/* Explicit SYSTEM-menu sample-area format. storage_request(completion*) may
 * be called ONLY by the affirmative device confirmation callback. No boot,
 * mount-failure or host request invokes it. Success requires a power cycle:
 * keep all sample consumers disabled until their caches/handles are rebuilt.
 *
 * Inject FS_STATUS, FS_RESULT, FS_MOUNTED, FS_FORMAT, FS_HASH, PROJECT_LOCK,
 * PROJECT_EPOCH. Addresses below are native DN2 1.11 / pinned R012 graft.
 * Status: 0 idle, 1 queued, 2 formatting, 3 verifying, 4 restart required,
 * negative = the result code. Result: 0 success; -1 not ready; -2 geometry;
 * -3 open files; -4 media read; -5 format failure; -6 header verification;
 * -7 prior media fault; -8 restart required; -9 queue failure.
 */
.text
.equ STORAGE_MMC_READY,0x4461b68c
.equ STORAGE_MMC_CAPACITY,0x4461b6b0
.equ STORAGE_MMC_READ,0x4012c59a
.equ STORAGE_OPEN_BUSY,0x46800b48
.equ STORAGE_IO_LATCH,0x47a19c90
.equ STORAGE_FIRST_LBA,0x005d8000
.equ STORAGE_END_LBA,0x02df0180

.global storage_request,storage_preflight,storage_format_work
.global storage_status,storage_result,storage_attempted,storage_native_result
.global storage_error_message

/* Fast non-mutating UI check; actual media and open-file checks run in worker.
 * D0=0 eligible, otherwise negative error. Does not imply confirmation. */
storage_preflight:
 tst.l storage_attempted
 bne.w storage_need_restart
 move.l FS_STATUS,%d0
 cmpi.l #2,%d0
 beq.s storage_check_media
 cmpi.l #-1,%d0
 bne.w storage_not_ready
storage_check_media:
 tst.l STORAGE_MMC_READY
 beq.w storage_not_ready
 move.l STORAGE_MMC_CAPACITY,%d0
 cmpi.l #STORAGE_END_LBA,%d0
 bcs.w storage_bad_geometry
 tst.l STORAGE_IO_LATCH
 bne.w storage_prior_fault
 moveq #0,%d0
 rts
storage_not_ready:
 moveq #-1,%d0
 rts
storage_bad_geometry:
 moveq #-2,%d0
 rts
storage_prior_fault:
 moveq #-7,%d0
 rts
storage_need_restart:
 moveq #-8,%d0
 rts

/* Native queue clones both std::function records before this returns.
 * The supplied completion owns its ProgressWindow using the stock lifetime.
 * D0=1 queued; D0=0 rejected and storage_result contains the reason. */
storage_request:
 move.l %a2,-(%sp)
 movea.l 8(%sp),%a2
 move.l storage_status,%d0
 cmpi.l #1,%d0
 beq.s storage_request_busy
 cmpi.l #2,%d0
 beq.s storage_request_busy
 cmpi.l #3,%d0
 beq.s storage_request_busy
 bsr.w storage_preflight
 tst.l %d0
 bne.s storage_request_reject
 moveq #1,%d0
 move.l %d0,storage_status
 clr.l storage_result
 jsr 0x4019e83a
 tst.l %d0
 beq.s storage_request_queue_failed
 move.l %a2,-(%sp)
 pea storage_work_function
 pea storage_job_name
 move.l %d0,-(%sp)
 jsr 0x400f2494
 lea 16(%sp),%sp
 tst.b %d0
 beq.s storage_request_queue_failed
 moveq #1,%d0
 movea.l (%sp)+,%a2
 rts
storage_request_busy:
 moveq #-1,%d0
 /* Do not overwrite an in-flight worker's status/result. */
 bra.s storage_request_return_false
storage_request_queue_failed:
 moveq #-9,%d0
storage_request_reject:
 move.l %d0,storage_status
 move.l %d0,storage_result
storage_request_return_false:
 moveq #0,%d0
 movea.l (%sp)+,%a2
 rts

/* Original DT2 formatter acquires its filesystem mutex and vetoes nonzero
 * open-file bitmap before writing. PROJECT_LOCK excludes our restore/browser/
 * host jobs. Its epoch also invalidates already queued jobs after formatting.
 * Native MMC write guards remain unchanged and protect stock project/presets.
 */
storage_format_work:
 lea -20(%sp),%sp
 movem.l %d2-%d5/%a2,(%sp)
 pea PROJECT_LOCK
 jsr 0x40001608
 addq.l #4,%sp
 bsr.w storage_preflight
 tst.l %d0
 bne.w storage_work_error
 move.l FS_STATUS,%d2
 move.l FS_MOUNTED,%d3
 move.l FS_RESULT,%d4
 jsr STORAGE_OPEN_BUSY
 tst.l %d0
 bne.w storage_work_open_files
 /* Check actual media access before any metadata write. No blank-only rule:
  * user explicitly confirmed erasing existing sample/other-mod storage. */
 bsr.w storage_read_header
 tst.l %d0
 bne.w storage_work_read_failed
 moveq #3,%d0
 move.l %d0,FS_STATUS
 moveq #2,%d0
 move.l %d0,storage_status
 moveq #1,%d0
 move.l %d0,storage_attempted
 addq.l #1,PROJECT_EPOCH
 clr.l -(%sp)
 jsr FS_FORMAT
 addq.l #4,%sp
 move.l %d0,storage_native_result
 tst.l %d0
 bne.w storage_work_format_rejected
 moveq #3,%d0
 move.l %d0,storage_status
 bsr.w storage_read_header
 tst.l %d0
 bne.w storage_work_verify_read_failed
 lea storage_header,%a2
 move.l (%a2),%d0
 cmpi.l #0x656b4653,%d0
 bne.w storage_work_bad_header
 move.l 4(%a2),%d0
 cmpi.l #4,%d0
 bne.w storage_work_bad_header
 move.l #0x31323334,-(%sp)
 pea 0x1fc.w
 move.l %a2,-(%sp)
 jsr FS_HASH
 lea 12(%sp),%sp
 cmp.l 0x1fc(%a2),%d0
 bne.w storage_work_bad_header
 /* Native format sets mounted=1 itself. Withhold it until reboot resets
  * cached directory enumerators, project loaders and sample assignments. */
 clr.l FS_MOUNTED
 moveq #3,%d0
 move.l %d0,FS_STATUS
 clr.l FS_RESULT
 moveq #4,%d0
 move.l %d0,storage_status
 clr.l storage_result
 moveq #0,%d5
 bra.w storage_work_unlock

storage_work_format_rejected:
 /* Pinned native formatter's only ordinary negative return is its open-file
  * veto, before writing. Do not restore availability after an I/O fault. */
 cmpi.l #-1,%d0
 bne.s storage_work_format_failed
 tst.l STORAGE_IO_LATCH
 bne.s storage_work_format_failed
 move.l %d2,FS_STATUS
 move.l %d3,FS_MOUNTED
 move.l %d4,FS_RESULT
 clr.l storage_attempted
storage_work_open_files:
 moveq #-3,%d0
 bra.s storage_work_error
storage_work_read_failed:
 moveq #-4,%d0
 bra.s storage_work_error
storage_work_format_failed:
 moveq #-5,%d0
 bra.s storage_work_unavailable
storage_work_verify_read_failed:
 moveq #-4,%d0
 bra.s storage_work_unavailable
storage_work_bad_header:
 moveq #-6,%d0
storage_work_unavailable:
 clr.l FS_MOUNTED
 moveq #3,%d1
 move.l %d1,FS_STATUS
 move.l %d0,FS_RESULT
storage_work_error:
 move.l %d0,storage_status
 move.l %d0,storage_result
 move.l %d0,%d5
storage_work_unlock:
 pea PROJECT_LOCK
 jsr 0x4000172a
 addq.l #4,%sp
 move.l %d5,%d0
 movem.l (%sp),%d2-%d5/%a2
 lea 20(%sp),%sp
 rts

storage_read_header:
 pea storage_header
 pea 512.w
 move.l #STORAGE_FIRST_LBA,-(%sp)
 jsr STORAGE_MMC_READ
 lea 12(%sp),%sp
 move.l %d0,storage_native_result
 rts

/* Stateless small std::function manager; no heap ownership to release. */
storage_work_manager:
 movea.l 4(%sp),%a0
 movea.l 8(%sp),%a1
 move.l 12(%sp),%d0
 tst.l %d0
 beq.s storage_manager_type
 cmpi.l #1,%d0
 beq.s storage_manager_pointer
 cmpi.l #2,%d0
 bne.s storage_manager_done
 move.l (%a1),(%a0)
 move.l 4(%a1),4(%a0)
 bra.s storage_manager_done
storage_manager_pointer:
 move.l %a1,(%a0)
 bra.s storage_manager_done
storage_manager_type:
 move.l #storage_work_type,(%a0)
storage_manager_done:
 moveq #0,%d0
 rts

/* UI can use this instead of generic ERROR after native completion cleanup. */
storage_error_message:
 move.l storage_result,%d0
 neg.l %d0
 cmpi.l #9,%d0
 bhi.s storage_message_unknown
 lea storage_messages,%a0
 move.l (%a0,%d0.l*4),%d0
 rts
storage_message_unknown:
 move.l #storage_msg_failure,%d0
 rts

.balign 4
storage_work_function:
 .long 0,0,storage_work_manager,storage_format_work
storage_work_type:
 .long 0x4020eeb4,storage_work_typename
storage_work_typename: .asciz "18Dn2SampleFormatJob"
storage_job_name: .asciz "Format sample storage"
storage_msg_success: .asciz "DONE - RESTART DN2"
storage_msg_ready: .asciz "SAMPLE STORAGE BUSY"
storage_msg_geometry: .asciz "UNSUPPORTED DRIVE SIZE"
storage_msg_open: .asciz "CLOSE SAMPLE TRANSFERS"
storage_msg_read: .asciz "DRIVE READ FAILED"
storage_msg_failure: .asciz "FORMAT FAILED - RESTART"
storage_msg_verify: .asciz "FORMAT VERIFY FAILED"
storage_msg_fault: .asciz "DRIVE ERROR - RESTART"
storage_msg_restart: .asciz "RESTART DN2 FIRST"
storage_msg_queue: .asciz "FORMAT COULD NOT START"
.balign 4
storage_messages:
 .long storage_msg_success,storage_msg_ready,storage_msg_geometry
 .long storage_msg_open,storage_msg_read,storage_msg_failure
 .long storage_msg_verify,storage_msg_fault,storage_msg_restart,storage_msg_queue
storage_status: .long 0
storage_result: .long 0
storage_attempted: .long 0
storage_native_result: .long 0
storage_header: .space 512
.balign 4
