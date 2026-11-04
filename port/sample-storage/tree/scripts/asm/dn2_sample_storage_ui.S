/* R013 sample-storage UI candidate. Native DN2 OS 1.11 ABI only.
 *
 * Hook: replace JSR 0x4012c140 at 0x4010bcd0 with JSR storage_ui_menu_hook.
 * A2 is SystemSettings' menu object. The hook appends one independent row,
 * then executes the displaced call. Existing FORMAT +DRIVE is unchanged.
 *
 * Bind storage_request(completion_std_function*) externally. It must copy
 * the completion before returning, return 1 if queued, 0 if rejected, and
 * invoke completion(capture, result) once: result >= 0 success, < 0 failure.
 * Its worker must serialize filesystem mutation and invalidate old handles.
 * This UI never calls a formatter, writes media, or changes FS_STATUS.
 */
.text
.global storage_ui_menu_hook,storage_ui_open_confirm,storage_ui_confirmed
.global storage_ui_menu_label,storage_ui_progress_label

storage_ui_menu_hook:
 link.w %a6,#-60
 movem.l %d2-%d3/%a2,-60(%a6)
 /* Two native std::function objects: on-press and enabled predicate. */
 pea storage_ui_open_confirm
 pea -16(%a6)
 bsr.w storage_ui_make_function
 addq.l #8,%sp
 tst.l %d0
 beq.w menu_done
 pea storage_ui_enabled
 pea -32(%a6)
 bsr.w storage_ui_make_function
 addq.l #8,%sp
 tst.l %d0
 beq.s menu_release_action
 pea 0x54.w
 jsr 0x40120264
 addq.l #4,%sp
 move.l %d0,%d3
 beq.s menu_release_functions
 /* Native SimpleMenuItem(this,title,action,font,enabled). */
 pea -32(%a6)
 pea 0x44645394
 pea -16(%a6)
 pea storage_ui_menu_label
 move.l %d3,-(%sp)
 jsr 0x40117224
 lea 20(%sp),%sp
 move.l %d3,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x4011690e
 addq.l #8,%sp
menu_release_functions:
 pea -32(%a6)
 jsr 0x40188086
 addq.l #4,%sp
menu_release_action:
 pea -16(%a6)
 jsr 0x40188086
 addq.l #4,%sp
menu_done:
 movem.l -60(%a6),%d2-%d3/%a2
 unlk %a6
 /* Returning D0 exactly as the displaced native call is required. */
 jmp 0x4012c140

storage_ui_enabled:
 moveq #1,%d0
 rts

/* make_function(destination16,invoker), returns bool.
 * Reuse the native SystemSettings 4-byte heap-capture manager. It copies
 * and deletes its capture; no custom std::function type/lifetime ABI.
 */
storage_ui_make_function:
 link.w %a6,#-4
 move.l %a2,-4(%a6)
 movea.l 8(%a6),%a2
 clr.l (%a2)
 clr.l 4(%a2)
 clr.l 8(%a2)
 clr.l 12(%a2)
 pea 4.w
 jsr 0x40120264
 addq.l #4,%sp
 tst.l %d0
 beq.s make_function_done
 movea.l %d0,%a0
 clr.l (%a0)
 move.l %d0,(%a2)
 move.l #0x4010b630,%d1
 move.l %d1,8(%a2)
 move.l 12(%a6),12(%a2)
 moveq #1,%d0
make_function_done:
 movea.l -4(%a6),%a2
 unlk %a6
 rts

/* Native menu actions run on clicked release, matching ConfirmWindow.
 * Opening, drawing, or answering NO cannot reach storage_request.
 */
storage_ui_open_confirm:
 link.w %a6,#-28
 move.l %a2,-28(%a6)
 pea storage_ui_confirmed
 pea -16(%a6)
 bsr.w storage_ui_make_function
 addq.l #8,%sp
 tst.l %d0
 beq.s confirm_done
 pea -16(%a6)
 pea storage_ui_confirm_detail
 pea storage_ui_confirm_title
 lea -24(%a6),%a0
 jsr 0x401a9e02
 lea 12(%sp),%sp
 tst.l -24(%a6)
 beq.s confirm_release
 pea -24(%a6)
 bsr.w storage_ui_present
 addq.l #4,%sp
confirm_release:
 pea -20(%a6)
 jsr 0x401880cc
 pea -16(%a6)
 jsr 0x40188086
 addq.l #8,%sp
confirm_done:
 movea.l -28(%a6),%a2
 unlk %a6
 rts

/* ConfirmWindow calls (capture, bool). Native big-endian ABI puts the
 * second argument's low byte at SP+11 before this function's prologue. */
storage_ui_confirmed:
 tst.b 11(%sp)
 beq.w confirmed_no
 link.w %a6,#-48
 movem.l %d2/%a2,-48(%a6)
 /* Native ProgressWindow factory returns shared_ptr in hidden A0. */
 pea storage_ui_progress_label
 lea -8(%a6),%a0
 jsr 0x401a7d3e
 addq.l #4,%sp
 tst.l -8(%a6)
 beq.w confirmed_release_progress
 /* Build stock formatter's completion closure. Capture owns a shared_ptr
 * to this progress view. Its manager retains/releases that exact owner. */
 clr.l -24(%a6)
 clr.l -20(%a6)
 clr.l -16(%a6)
 clr.l -12(%a6)
 pea 8.w
 jsr 0x40120264
 addq.l #4,%sp
 move.l %d0,%d2
 beq.s confirmed_release_progress
 pea -8(%a6)
 move.l %d2,-(%sp)
 jsr 0x401a7794
 addq.l #8,%sp
 move.l %d2,-24(%a6)
 move.l #0x40098cca,%d0
 move.l %d0,-16(%a6)
 move.l #storage_ui_completed,%d0
 move.l %d0,-12(%a6)
 /* Publish modal view before worker can complete. */
 pea -8(%a6)
 bsr.w storage_ui_present
 addq.l #4,%sp
 tst.b %d0
 beq.s confirmed_release_completion
 pea -24(%a6)
 jsr storage_request
 addq.l #4,%sp
 tst.l %d0
 bne.s confirmed_release_completion
 /* Rejection still closes the progress window and uses native ERROR. */
 pea -1.w
 pea -24(%a6)
 bsr.w storage_ui_completed
 addq.l #8,%sp
confirmed_release_completion:
 pea -24(%a6)
 jsr 0x40188086
 addq.l #4,%sp
confirmed_release_progress:
 pea -4(%a6)
 jsr 0x401880cc
 addq.l #4,%sp
 movem.l -48(%a6),%d2/%a2
 unlk %a6
confirmed_no:
 rts

/* Replace the progress view only after the result modal is adopted. Any
 * completed/partial format requires a restart-only modal; a rejected
 * precondition gets a dismissable explanation. Allocation/adoption failure
 * leaves the original key-blocking progress modal in place.
 * Native std::function capture manager owns the progress shared_ptr here. */
.global storage_ui_completed,storage_ui_restart_event
storage_ui_completed:
 link.w %a6,#-44
 movem.l %d2-%d3/%a2,-44(%a6)
 movea.l 8(%a6),%a0
 movea.l (%a0),%a0
 movea.l (%a0),%a2
 clr.l -16(%a6)
 clr.l -12(%a6)
 clr.l -8(%a6)
 clr.l -4(%a6)
 move.l #storage_ui_restart_title,%d2
 move.l #storage_ui_restart_detail,%d3
 tst.l 12(%a6)
 bpl.s completed_build_message
 tst.l storage_attempted
 beq.s completed_rejected
 move.l #storage_ui_partial_title,%d2
 bra.s completed_build_message
completed_rejected:
 move.l #storage_ui_error_title,%d2
 jsr storage_error_message
 move.l %d0,%d3
 pea storage_ui_ignore_answer
 pea -16(%a6)
 bsr.w storage_ui_make_function
 addq.l #8,%sp
 tst.l %d0
 beq.s completed_done
completed_build_message:
 pea -16(%a6)
 move.l %d3,-(%sp)
 move.l %d2,-(%sp)
 lea -24(%a6),%a0
 jsr 0x401a9e02
 lea 12(%sp),%sp
 movea.l -24(%a6),%a0
 move.l %a0,%d0
 beq.s completed_release
 tst.l 12(%a6)
 bpl.s completed_lock_message
 tst.l storage_attempted
 beq.s completed_present_message
completed_lock_message:
 move.l #storage_ui_restart_vtable,(%a0)
completed_present_message:
 pea -24(%a6)
 bsr.w storage_ui_present
 addq.l #4,%sp
 tst.b %d0
 beq.s completed_release
 movea.l (%a2),%a1
 move.l %a2,-(%sp)
 movea.l 40(%a1),%a0
 jsr (%a0)
 addq.l #4,%sp
completed_release:
 pea -20(%a6)
 jsr 0x401880cc
 addq.l #4,%sp
 pea -16(%a6)
 jsr 0x40188086
 addq.l #4,%sp
completed_done:
 movem.l -44(%a6),%d2-%d3/%a2
 unlk %a6
 rts
storage_ui_ignore_answer:
 rts

/* Absorb keys on this instance only: a YES/NO dialog normally dismisses on
 * release. No route should expose stale handles before the requested reboot.
 */
storage_ui_restart_event:
 moveq #1,%d0
 rts

/* present(shared_ptr<View>*), preserving its local caller-owned reference.
 * Exact stock format/reload confirmation controller route. */
storage_ui_present:
 link.w %a6,#-4
 move.l %a2,-4(%a6)
 movea.l 8(%a6),%a2
 jsr 0x4018c8dc
 move.l %d0,-(%sp)
 jsr 0x4002c47a
 addq.l #4,%sp
 clr.l -(%sp)
 move.l %a2,-(%sp)
 move.l %d0,-(%sp)
 jsr 0x4011d71e
 lea 12(%sp),%sp
 movea.l -4(%a6),%a2
 unlk %a6
 rts

.balign 4
storage_ui_menu_label:
 .asciz "FORMAT SAMPLES"
storage_ui_confirm_title:
 .asciz "ERASE SAMPLE AREA?"
storage_ui_confirm_detail:
 .asciz "INCL. OTHER MODS. Y/N"
storage_ui_progress_label:
 .asciz "FORMATTING SAMPLES"
storage_ui_restart_title:
 .asciz "SAMPLES FORMATTED"
storage_ui_restart_detail:
 .asciz "SWITCH OFF / ON DN2"
storage_ui_error_title:
 .asciz "FORMAT NOT STARTED"
storage_ui_partial_title:
 .asciz "FORMAT INCOMPLETE"
.balign 4
/* Exact native ConfirmWindow primary table 0x4020625c..0x402062a8;
 * only event entry 2 changes. Keep native destructors, drawing and RTTI. */
 .long 0,0x4020623c
storage_ui_restart_vtable:
 .long 0x401b99ba,0x401b9a5c,storage_ui_restart_event,0x4011c638
 .long 0x401128c8,0x4011ca46,0x4011c644,0x4011cab6
 .long 0x4011c650,0x4011c65c,0x4011c85e,0x4011c666
 .long 0x4011c668,0x4011c66c,0x4011c670,0x4011cbe4,0x4011cbf0
.balign 4
