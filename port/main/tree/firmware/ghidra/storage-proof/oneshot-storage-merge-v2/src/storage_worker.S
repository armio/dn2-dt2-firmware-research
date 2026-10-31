/* Explicit one-shot file load. Native file work occurs only from the UI task.
 * Media waits are native and non-preemptible; the software deadline cannot
 * guarantee UI latency. No filesystem format/write API is called here.
 */
.equ S, 0x47a56000
.equ FRAME, S+0x100
.equ SOURCE, 0x47a3a000
.equ BUFFER, 0x47a46000
.equ BANK_BYTES, 47104
.equ FS_INIT, 0x47a19ca4
.equ MOUNTED, 0x46b9608c
.equ FRAMES, 0x4058e8d4
.equ CONTROL, 0x80005e60
.equ REPLY_ACK, 0x800053bc
.equ PHASE, S+4
.equ ATTEMPT, S+8
.equ ERROR, S+12
.equ NATIVE_RC, S+16
.equ READ_BYTES, S+20
.equ CURSOR, S+24
.equ VERIFIED, S+28
.equ FULLSUM, S+32
.equ TX_STATE, S+36
.equ SEQ, S+40
.equ SENT_AT, S+44
.equ TIMEOUTS, S+48
.equ REFUSALS, S+52
.equ SENT, S+56
.equ ACKED, S+60
.equ TX_BYTES, S+64
.equ TX_DEST, S+68
.equ TX_KIND, S+72
.equ TX_OFFSET, S+76
.equ STARTED, S+80
.equ LAST_POLL, S+84
.equ TRANSPORT_A, S+88
.equ TRANSPORT_B, S+92
.equ CURRENT_FRAME, S+96
.equ LAST_QUIET, S+100
.equ POLLS, S+104
.equ FILE_SIZE, S+108
.equ CLOSE_RC, S+112
.equ EOF_RC, S+120
.equ REQUEST_FRAME, S+124
.equ HANDLE, S+128
.equ EOF_BYTE, S+144
.equ ERROR_PHASE, S+148
.equ DEADLINE, S+152
.equ NATIVE_CALLS, S+156
.equ FS_INIT_SNAPSHOT, S+160
.equ MOUNTED_SNAPSHOT, S+164

.macro store value,address
move.l #\value,%d0
move.l %d0,\address
.endm
.macro native address
addq.l #1,NATIVE_CALLS
jsr \address
move.l %d0,NATIVE_RC
.endm
.macro phase value
store \value,PHASE
.endm
.macro fail value
moveq #\value,%d0
bsr.w os_set_error
bra.w os_poll_cleanup
.endm

.text
.globl os_ui_hook,os_request,os_frame_hook,os_poll,os_frame_src
os_ui_hook:
lea -16(%sp),%sp
movem.l %d0-%d1/%a0-%a1,(%sp)
jsr os_poll
movem.l (%sp),%d0-%d1/%a0-%a1
lea 16(%sp),%sp
jmp 0x4011d2f4

/* The probe's old unknown-command arm calls here instead of emitting status2.
 * d2=command-3,d5=unpacked length,a2=reply,a1=payload. No I/O is done here.
 */
os_request:
cmpi.l #1,%d2
bne.w request_unknown
cmpi.l #3,%d5
bne.w request_bad_length
tst.l ATTEMPT
bne.w request_refused
tst.l 0x402876f8
bne.w request_refused
bsr.w os_transport
tst.l %d0
bne.w request_refused
tst.l FS_INIT
bne.w request_refused
store 1,ATTEMPT
move.l FRAMES,%d0
move.l %d0,STARTED
move.l %d0,REQUEST_FRAME
store 90000,DEADLINE
store 0x46816f8c,CURSOR
phase 1
bra.w request_snapshot
request_refused:
moveq #1,%d0
move.b %d0,3(%a2)
request_snapshot:
lea S,%a0
move.l (%a0)+,(%a1)+
move.l (%a0)+,(%a1)+
move.l (%a0)+,(%a1)+
move.l (%a0)+,(%a1)+
rts
request_bad_length:
moveq #1,%d0
move.b %d0,3(%a2)
rts
request_unknown:
moveq #2,%d0
move.b %d0,3(%a2)
rts

/* Exact native conservative activity predicate, with both inputs retained. */
os_transport:
move.l 0x42c5a994,%d0
move.l %d0,TRANSPORT_A
move.l 0x42c5a918,%d0
move.l %d0,TRANSPORT_B
jsr 0x400d855c
rts

/* d0=error; retain the first cause even if a close later also fails. */
os_set_error:
tst.l ERROR
bne.s error_already
move.l %d0,ERROR
move.l PHASE,%d0
move.l %d0,ERROR_PHASE
store 4,TX_STATE
error_already:
rts

os_poll:
lea -40(%sp),%sp
movem.l %d2-%d7/%a2-%a5,(%sp)
addq.l #1,POLLS
move.l FRAMES,%d0
move.l %d0,LAST_POLL
move.l FS_INIT,%d0
move.l %d0,FS_INIT_SNAPSHOT
moveq #-1,%d1
tst.l %d0
beq.s poll_no_mount
move.l MOUNTED,%d1
poll_no_mount:
move.l %d1,MOUNTED_SNAPSHOT
move.l PHASE,%d0
beq.w os_poll_done
cmpi.l #16,%d0
bcc.w os_poll_done
tst.l ERROR
bne.w os_poll_cleanup
bsr.w os_transport
tst.l %d0
beq.s poll_transport_ok
fail 2
poll_transport_ok:
move.l FRAMES,%d0
sub.l STARTED,%d0
cmpi.l #90000,%d0
bcs.s poll_deadline_ok
fail 14
poll_deadline_ok:
move.l PHASE,%d0
cmpi.l #1,%d0
beq.w poll_clear_old
cmpi.l #2,%d0
beq.w poll_clear_new
cmpi.l #3,%d0
beq.w poll_clear_buffer
cmpi.l #4,%d0
beq.w poll_premount
cmpi.l #5,%d0
beq.w poll_mount
cmpi.l #6,%d0
beq.w poll_open
cmpi.l #7,%d0
beq.w poll_size
cmpi.l #8,%d0
beq.w poll_read
cmpi.l #9,%d0
beq.w poll_eof
cmpi.l #10,%d0
beq.w poll_close
cmpi.l #11,%d0
beq.w poll_verify
cmpi.l #12,%d0
beq.w poll_begin
cmpi.l #13,%d0
beq.w poll_wait
cmpi.l #14,%d0
beq.w poll_chunk
cmpi.l #15,%d0
beq.w poll_commit
fail 15

/* At most64KiB cleared per UI pass, without masking interrupts. */
poll_clear_old:
move.l #0x47a19ca0,%d2
bsr.w clear_slice
bne.w os_poll_done
store 0x47a1a000,CURSOR
phase 2
bra.w os_poll_done
poll_clear_new:
move.l #0x47a35200,%d2
bsr.w clear_slice
bne.w os_poll_done
store BUFFER,CURSOR
phase 3
bra.w os_poll_done
poll_clear_buffer:
move.l #BUFFER+BANK_BYTES,%d2
bsr.w clear_slice
bne.w os_poll_done
phase 4
bra.w os_poll_done
clear_slice:
movea.l CURSOR,%a0
move.l %a0,%d1
sub.l %d1,%d2
cmpi.l #65536,%d2
bls.s clear_size_ok
move.l #65536,%d2
clear_size_ok:
move.l %d2,%d1
lsr.l #2,%d1
clear_loop:
clr.l (%a0)+
subq.l #1,%d1
bne.s clear_loop
move.l %a0,CURSOR
/* Return NZ while there is a full slice left; the caller's endpoint is
 * recovered from its phase, so an exact64KiB final slice still terminates. */
move.l PHASE,%d0
cmpi.l #1,%d0
bne.s clear_not_old
cmpa.l #0x47a19ca0,%a0
rts
clear_not_old:
cmpi.l #2,%d0
bne.s clear_not_new
cmpa.l #0x47a35200,%a0
rts
clear_not_new:
cmpa.l #BUFFER+BANK_BYTES,%a0
rts

poll_premount:
native 0x46802baa
store 1,FS_INIT
phase 5
bra.w os_poll_done
poll_mount:
pea 1.w
native 0x46802bc0
addq.l #4,%sp
tst.l %d0
bne.w mount_bad
move.l MOUNTED,%d0
cmpi.l #1,%d0
bne.w mount_bad
phase 6
bra.w os_poll_done
mount_bad:
fail 4
poll_open:
pea HANDLE
pea mode_r
pea sample_path
native 0x47a3648e
lea 12(%sp),%sp
tst.l %d0
bne.w open_bad
move.l HANDLE+12,%d0
cmpi.l #1,%d0
bne.w open_bad
tst.l HANDLE+8
bne.w open_bad
phase 7
bra.w os_poll_done
open_bad:
fail 5
poll_size:
move.l HANDLE,-(%sp)
native 0x47a3682e
addq.l #4,%sp
move.l %d0,FILE_SIZE
cmpi.l #BANK_BYTES,%d0
bne.w size_bad
phase 8
bra.w os_poll_done
size_bad:
fail 6
poll_read:
move.l #BANK_BYTES,%d2
sub.l READ_BYTES,%d2
cmpi.l #2048,%d2
bls.s read_count_ok
move.l #2048,%d2
read_count_ok:
move.l READ_BYTES,%d3
add.l #BUFFER,%d3
pea HANDLE
move.l %d2,-(%sp)
move.l %d3,-(%sp)
native 0x47a36246
lea 12(%sp),%sp
cmp.l %d2,%d0
bne.w read_bad
add.l READ_BYTES,%d2
move.l %d2,READ_BYTES
cmp.l HANDLE+4,%d2
bne.w offset_bad
cmpi.l #BANK_BYTES,%d2
bne.w os_poll_done
phase 9
bra.w os_poll_done
read_bad:
fail 7
offset_bad:
fail 8
poll_eof:
store 0xa5a5a5a5,EOF_BYTE
pea HANDLE
pea 1.w
pea EOF_BYTE
native 0x47a36246
lea 12(%sp),%sp
move.l %d0,EOF_RC
tst.l %d0
bne.w eof_bad
move.l HANDLE+4,%d0
cmpi.l #BANK_BYTES,%d0
bne.w offset_bad
move.l EOF_BYTE,%d0
cmpi.l #0xa5a5a5a5,%d0
bne.w eof_bad
phase 10
bra.w os_poll_done
eof_bad:
fail 9
poll_close:
pea HANDLE
native 0x47a3644c
addq.l #4,%sp
move.l %d0,CLOSE_RC
tst.l %d0
bne.w close_bad
tst.l HANDLE+12
bne.w close_bad
phase 11
bra.w os_poll_done
close_bad:
fail 10

/* Compare against the pinned immutable file copy; DSP consumes BUFFER only.
 * Accumulate the protocol's little-endian32 sum over the complete47KiB file. */
poll_verify:
move.l VERIFIED,%d3
lea BUFFER,%a0
adda.l %d3,%a0
lea SOURCE,%a1
adda.l %d3,%a1
move.l #BANK_BYTES,%d2
sub.l %d3,%d2
cmpi.l #4096,%d2
bls.s verify_count_ok
move.l #4096,%d2
verify_count_ok:
add.l %d2,%d3
lsr.l #2,%d2
move.l FULLSUM,%d4
verify_loop:
move.l (%a0)+,%d0
cmp.l (%a1)+,%d0
bne.w verify_bad
bsr.w byte_pair_swap
swap %d0
add.l %d0,%d4
subq.l #1,%d2
bne.s verify_loop
move.l %d4,FULLSUM
move.l %d3,VERIFIED
cmpi.l #BANK_BYTES,%d3
bne.w os_poll_done
phase 12
bra.w os_poll_done
verify_bad:
fail 11
byte_pair_swap:
move.l %d0,%d1
and.l #0x00ff00ff,%d0
lsl.l #8,%d0
lsr.l #8,%d1
and.l #0x00ff00ff,%d1
or.l %d1,%d0
rts

poll_begin:
store 0x4f420001,SEQ
store 0xffffffff,TX_DEST
store 0,TX_BYTES
store 1,TX_KIND
bra.w prepare_frame
poll_chunk:
addq.l #1,SEQ
move.l TX_OFFSET,%d0
move.l %d0,TX_DEST
move.l #BANK_BYTES,%d1
sub.l %d0,%d1
cmpi.l #2560,%d1
bls.s chunk_count_ok
move.l #2560,%d1
chunk_count_ok:
move.l %d1,TX_BYTES
store 2,TX_KIND
bra.w prepare_frame
poll_commit:
addq.l #1,SEQ
store 0xfffffffc,TX_DEST
store 0,TX_BYTES
store 3,TX_KIND
prepare_frame:
lea FRAME,%a0
move.l #672,%d1
frame_clear_loop:
clr.l (%a0)+
subq.l #1,%d1
bne.s frame_clear_loop
moveq #4,%d0
move.w %d0,FRAME
move.l TX_BYTES,%d2
lsr.l #2,%d2
move.w %d2,FRAME+2
move.l TX_DEST,%d0
swap %d0
move.l %d0,FRAME+4
move.l SEQ,%d0
swap %d0
move.l %d0,FRAME+8
tst.l %d2
beq.s frame_control_sum
lea BUFFER,%a0
move.l TX_OFFSET,%d0
adda.l %d0,%a0
lea FRAME+16,%a1
moveq #0,%d4
frame_payload_loop:
move.l (%a0)+,%d0
bsr.w byte_pair_swap
move.l %d0,(%a1)+
swap %d0
add.l %d0,%d4
subq.l #1,%d2
bne.s frame_payload_loop
bra.s frame_sum_ready
frame_control_sum:
move.l FULLSUM,%d4
frame_sum_ready:
swap %d4
move.l %d4,FRAME+12
phase 13
/* Publish only after the complete immutable frame is constructed. */
store 1,TX_STATE
bra.w os_poll_done
poll_wait:
move.l TX_STATE,%d0
cmpi.l #3,%d0
bne.w os_poll_done
store 0,TX_STATE
move.l TX_KIND,%d0
cmpi.l #3,%d0
beq.s load_success
cmpi.l #1,%d0
beq.s next_chunk
move.l TX_OFFSET,%d0
add.l TX_BYTES,%d0
move.l %d0,TX_OFFSET
cmpi.l #BANK_BYTES,%d0
beq.s next_commit
next_chunk:
phase 14
bra.w os_poll_done
next_commit:
phase 15
bra.w os_poll_done
load_success:
phase 16
bra.w os_poll_done

os_poll_cleanup:
tst.l HANDLE+12
beq.s cleanup_done
pea HANDLE
native 0x47a3644c
addq.l #4,%sp
move.l %d0,CLOSE_RC
cleanup_done:
phase 255
os_poll_done:
movem.l (%sp),%d2-%d7/%a2-%a5
lea 40(%sp),%sp
rts

/* ISR: only a prepared-frame selection and acknowledgement state machine.
 * No native filesystem, mutex, allocation or media call is reachable here.
 */
os_frame_hook:
move.l 0x402876f8,%d0
bne.s frame_skip
jsr os_frame_src
pea 0x800053a4
pea 0xabc.w
move.l %d0,-(%sp)
pea 0xa80.w
jsr 0x400cf7be
lea 16(%sp),%sp
jmp 0x40025eb2
frame_skip:
subq.l #1,%d0
move.l %d0,0x402876f8
jmp 0x40025eb2

os_frame_src:
lea -40(%sp),%sp
movem.l %d2-%d7/%a2-%a5,(%sp)
move.l FRAMES,%d0
move.l %d0,CURRENT_FRAME
bsr.w os_transport
move.l PHASE,%d1
beq.w frame_stock
cmpi.l #16,%d1
bcc.w frame_stock
tst.l ERROR
bne.w frame_stock
tst.l %d0
beq.s frame_transport_ok
moveq #2,%d0
bsr.w os_set_error
bra.w frame_stock
frame_transport_ok:
move.l FRAMES,%d0
sub.l STARTED,%d0
cmpi.l #90000,%d0
bcs.s frame_deadline_ok
moveq #14,%d0
bsr.w os_set_error
bra.w frame_stock
frame_deadline_ok:
move.l TX_STATE,%d0
cmpi.l #2,%d0
bne.w frame_check_ready
/* A reply trails the transmit by multiple exchanges. Do not count the stale
 * refusal still in word6 immediately after retrying the same sequence. */
move.l FRAMES,%d0
sub.l SENT_AT,%d0
cmpi.l #4,%d0
bcs.w frame_check_ready
move.l REPLY_ACK,%d0
move.l SEQ,%d1
cmp.l %d1,%d0
beq.s frame_ack
eor.l #0x80000000,%d1
cmp.l %d1,%d0
beq.s frame_refused
move.l FRAMES,%d0
sub.l SENT_AT,%d0
cmpi.l #24,%d0
bcs.w frame_check_ready
addq.l #1,TIMEOUTS
move.l TIMEOUTS,%d0
cmpi.l #8,%d0
bcs.s frame_retry
moveq #12,%d0
bsr.w os_set_error
bra.w frame_stock
frame_refused:
addq.l #1,REFUSALS
move.l REFUSALS,%d0
cmpi.l #3,%d0
bcs.s frame_retry
moveq #13,%d0
bsr.w os_set_error
bra.w frame_stock
frame_retry:
store 1,TX_STATE
bra.s frame_check_ready
frame_ack:
addq.l #1,ACKED
store 3,TX_STATE
frame_check_ready:
/* Aligned long reads cover all four native event masks at bytes34..41. */
move.l CONTROL+32,%d0
and.l #0xffff,%d0
or.l CONTROL+36,%d0
move.l CONTROL+40,%d1
and.l #0xffff0000,%d1
or.l %d1,%d0
bne.s frame_events
move.l LAST_QUIET,%d1
store 1,LAST_QUIET
tst.l %d1
beq.s frame_stock
move.l TX_STATE,%d0
cmpi.l #1,%d0
bne.s frame_stock
move.l FRAMES,%d0
move.l %d0,SENT_AT
addq.l #1,SENT
store 2,TX_STATE
move.l #FRAME,%d0
bra.s frame_return
frame_events:
store 0,LAST_QUIET
frame_stock:
move.l #CONTROL,%d0
frame_return:
movem.l (%sp),%d2-%d7/%a2-%a5
lea 40(%sp),%sp
rts

.balign 4
.globl worker_code_end
worker_code_end:
mode_r: .asciz "r"
sample_path: .asciz "/sample_bank_3slot_20261008_v1.osb"
.balign 4
.globl worker_image_end
worker_image_end:
