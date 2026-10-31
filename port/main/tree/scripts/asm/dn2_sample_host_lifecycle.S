/* Separate FsRequestHandler state for each native MidiRpcDispatcher.
 * The stock dispatcher owns its data handler at +0x10. Never overlay it.
 * Calls arrive through the stock serialized RPC worker; teardown follows the
 * native owner's existing lifetime. Heap entries are {next, owner, state[0x19c]}.
 */
.text
.global sample_host_init,sample_host_destroy,sample_host_get,sample_host_release
.global sample_host_route,sample_host_native_destroy,sample_host_registry
.global sample_host_collect
.ifdef HOST_EPOCH
.equ ENTRY_BYTES,0x1a8
.else
.equ ENTRY_BYTES,0x1a4
.endif
sample_host_init:
 move.l %a2,-(%sp)
 movea.l 8(%sp),%a2
 move.l %a2,-(%sp)
 jsr WRITER_INIT
 pea 0x30(%a2)
 jsr ENUM_INIT
 pea 0x54(%a2)
 jsr DIRECTORY_INIT
 lea 12(%sp),%sp
 moveq #11,%d0
 move.l %d0,0x190(%a2)
 movea.l (%sp)+,%a2
 rts

sample_host_destroy:
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 movea.l 12(%sp),%a2
 pea 0x54(%a2)
 jsr DIRECTORY_DESTROY
 addq.l #4,%sp
 movea.l 0x50(%a2),%a3
 tst.l %a3
 beq.s destroy_reader
 pea 12(%a3)
 jsr 0x4018b1c6
 move.l %a3,-(%sp)
 jsr 0x40120270
 addq.l #8,%sp
 clr.l 0x50(%a2)
destroy_reader:
 movea.l 0x4c(%a2),%a0
 tst.l %a0
 beq.s destroy_writer
 movea.l (%a0),%a1
 move.l %a0,-(%sp)
 movea.l 4(%a1),%a1
 jsr (%a1)
 addq.l #4,%sp
 clr.l 0x4c(%a2)
destroy_writer:
 /* Enumerator's original destructor40127B72 is RTS. */
 move.l %a2,-(%sp)
 jsr WRITER_DESTROY
 addq.l #4,%sp
 movea.l (%sp)+,%a2
 movea.l (%sp)+,%a3
 rts

sample_host_get:
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 movea.l 12(%sp),%a3
 jsr sample_host_collect
 movea.l sample_host_registry,%a2
get_find:
 tst.l %a2
 beq.s get_create
 cmpa.l 4(%a2),%a3
 beq.s get_found
 movea.l (%a2),%a2
 bra.s get_find
get_create:
 jsr CALLBACKS_INIT
 pea ENTRY_BYTES.w
 jsr 0x40120264
 addq.l #4,%sp
 tst.l %d0
 beq.s get_return
 movea.l %d0,%a2
 pea ENTRY_BYTES.w
 clr.l -(%sp)
 move.l %a2,-(%sp)
 jsr 0x401344d8
 lea 12(%sp),%sp
 move.l %a3,4(%a2)
 pea 8(%a2)
 jsr sample_host_init
 addq.l #4,%sp
 move.l sample_host_registry,(%a2)
 move.l %a2,sample_host_registry
get_found:
 move.l %a2,%d0
 addq.l #8,%d0
get_return:
 movea.l (%sp)+,%a2
 movea.l (%sp)+,%a3
 rts

sample_host_release:
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 lea sample_host_registry,%a3
release_find:
 movea.l (%a3),%a2
 tst.l %a2
 beq.s release_done
 move.l 4(%a2),%d0
 cmp.l 12(%sp),%d0
 beq.s release_found
 movea.l %a2,%a3
 bra.s release_find
release_found:
 movea.l %a2,%a0
 bsr.w sample_host_pending
 tst.l %d0
 beq.s release_now
 /* DT2 jobs and their UI completion capture the state by raw pointer.
  * Detach the owner but retain state until that final callback finishes. */
 clr.l 4(%a2)
 bra.s release_done
release_now:
 move.l (%a2),(%a3)
 pea 8(%a2)
 jsr sample_host_destroy
 move.l %a2,-(%sp)
 jsr 0x40120270
 addq.l #8,%sp
release_done:
 movea.l (%sp)+,%a2
 movea.l (%sp)+,%a3
 rts

/* Registry mutations remain on the native RPC owner's path. Completion
 * callbacks only clear their original flags; they never unlink entries. */
sample_host_collect:
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 lea sample_host_registry,%a3
collect_next:
 movea.l (%a3),%a2
 tst.l %a2
 beq.s collect_done
 tst.l 4(%a2)
 bne.s collect_keep
 movea.l %a2,%a0
 bsr.w sample_host_pending
 tst.l %d0
 bne.s collect_keep
 move.l (%a2),(%a3)
 pea 8(%a2)
 jsr sample_host_destroy
 move.l %a2,-(%sp)
 jsr 0x40120270
 addq.l #8,%sp
 bra.s collect_next
collect_keep:
 movea.l %a2,%a3
 bra.s collect_next
collect_done:
 movea.l (%sp)+,%a2
 movea.l (%sp)+,%a3
 rts

/* A0=registry entry; D0=true until assignment UI completion or clear job's
 * final state write. Offsets include the eight-byte registry header. */
sample_host_pending:
 tst.b 0x18d(%a0)
 bne.s pending_yes
 tst.b 0x19c(%a0)
 beq.s pending_no
 tst.b 0x19d(%a0)
 seq %d0
 andi.l #1,%d0
 rts
pending_yes:
 moveq #1,%d0
 rts
pending_no:
 moveq #0,%d0
 rts

sample_host_route:
 link.w %a6,#-16
 movem.l %d2/%a2-%a4,(%sp)
 movea.l %a0,%a2
 movea.l 8(%a6),%a3
 movea.l 12(%a6),%a4
 move.l FS_STATUS,%d0
 cmpi.l #2,%d0
 bne.s route_stock
 pea -16(%a3)
 jsr sample_host_get
 addq.l #4,%sp
 tst.l %d0
 beq.s route_stock
.ifdef HOST_EPOCH
 /* Each request snapshots the project generation before the DT2 handler
  * reads the current project. Enqueue copies this stamp into its own capture. */
 movea.l %d0,%a0
 move.l HOST_EPOCH,%d1
 move.l %d1,0x19c(%a0)
.endif
 move.l %a4,-(%sp)
 move.l %d0,-(%sp)
 movea.l %a2,%a0
 jsr SAMPLE_DISPATCH
 addq.l #8,%sp
 tst.l (%a2)
 beq.s route_stock
 move.l %a2,%d0
 movem.l (%sp),%d2/%a2-%a4
 unlk %a6
 rts
route_stock:
 movea.l %a2,%a0
 movem.l (%sp),%d2/%a2-%a4
 unlk %a6
 jmp 0x40128a9a

sample_host_native_destroy:
 move.l 4(%sp),-(%sp)
 jsr sample_host_release
 addq.l #4,%sp
 /* Displaced stock destructor prologue4012549A..401254A2. */
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 movea.l 12(%sp),%a2
 jmp 0x401254a2
.balign 4
sample_host_registry:
 .long 0
