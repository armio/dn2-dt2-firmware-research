/* Active table and serialized active mirror have distinct companions.
 * UID changes on native load; raw ownership, not the UID, identifies live data.
 */
.text
.global sample_project_state,sample_project_serial_entry,sample_project_publish
.global sample_project_deserialize,sample_project_serialize,sample_project_blank
.global sample_project_settings_raw
sample_project_state:
 move.l PROJECT_STATE,%d0
 bne.s project_state_done
 move.l %a2,-(%sp)
 move.l #0x8420,-(%sp)
 jsr 0x40120264
 addq.l #4,%sp
 move.l %d0,%a2
 tst.l %d0
 beq.s project_state_restore
 move.l #0x8420,-(%sp)
 clr.l -(%sp)
 move.l %a2,-(%sp)
 jsr 0x401344d8
 lea 12(%sp),%sp
 move.l %a2,PROJECT_STATE
project_state_restore:
 move.l %a2,%d0
 move.l (%sp)+,%a2
project_state_done:
 rts

/* (serialized*) -> companion or 0 for an unassociated temporary buffer. */
sample_project_serial_entry:
 move.l 4(%sp),%d0
 cmpi.l #0x405cd96c,%d0
 bne.s project_serial_cache
 jsr sample_project_state
 tst.l %d0
 beq.s project_serial_done
 addi.l #0x4210,%d0
project_serial_done:
 rts
project_serial_cache:
 jmp CACHE_ENTRY

/* (destination entry, source entry or 0=empty, owner, UID, slot) -> true.
 * The valid bit is published only after the complete table/header exists.
 */
sample_project_publish:
 lea -16(%sp),%sp
 movem.l %d2/%a2-%a4,(%sp)
 move.l 20(%sp),%a2
 move.l 24(%sp),%a3
 move.l 32(%sp),%d2
 clr.l 4(%a2)
 move.l 28(%sp),12(%a2)
 move.l %d2,8(%a2)
 move.l 36(%sp),(%a2)
 lea 528(%a2),%a4
 move.l #16384,-(%sp)
 tst.l %a3
 beq.s project_publish_empty
 lea 528(%a3),%a0
 move.l %a0,-(%sp)
 move.l %a4,-(%sp)
 jsr 0x40134490
 bra.s project_publish_header
project_publish_empty:
 moveq #-1,%d0
 move.l %d0,-(%sp)
 move.l %a4,-(%sp)
 jsr 0x401344d8
project_publish_header:
 lea 12(%sp),%sp
 move.l %a4,-(%sp)
 move.l %d2,-(%sp)
 lea 16(%a2),%a0
 move.l %a0,-(%sp)
 jsr RECORD_PREPARE
 lea 12(%sp),%sp
 moveq #1,%d0
 move.l %d0,4(%a2)
 movem.l (%sp),%d2/%a2-%a4
 lea 16(%sp),%sp
 rts

/* (raw destination, serialized source, callback) -> native bool. */
sample_project_deserialize:
 lea -20(%sp),%sp
 movem.l %d2/%a2-%a5,(%sp)
 move.l 24(%sp),%a2
 move.l 28(%sp),%a3
 suba.l %a4,%a4
 suba.l %a5,%a5
 move.l 0x446478d0,%d0
 beq.w project_deserialize_native
 move.l %d0,%a0
 cmp.l 16(%a0),%a2
 bne.w project_deserialize_native
 jsr sample_project_state
 tst.l %d0
 beq.w project_deserialize_fail
 move.l %d0,%a4
 move.l %a3,-(%sp)
 jsr sample_project_serial_entry
 addq.l #4,%sp
 move.l %d0,%a5
 tst.l %d0
 beq.s project_deserialize_native
 tst.l 4(%a5)
 beq.s project_deserialize_fail
 move.l 24(%a3),%d0
 cmp.l 8(%a5),%d0
 bne.s project_deserialize_fail
 cmpa.l #0x405cd96c,%a3
 beq.s project_deserialize_native
 move.l -12(%a3),%d0
 cmp.l (%a5),%d0
 bne.s project_deserialize_fail
project_deserialize_native:
 move.l 32(%sp),-(%sp)
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 jsr NATIVE_DESERIALIZE
 lea 12(%sp),%sp
 move.l %d0,%d2
 tst.l %a4
 beq.s project_deserialize_done
 clr.l 4(%a4)
 tst.b %d2
 beq.s project_deserialize_done
 move.l #128,-(%sp)
 move.l 8(%a2),-(%sp)
 move.l %a2,-(%sp)
 move.l %a5,-(%sp)
 move.l %a4,-(%sp)
 jsr sample_project_publish
 lea 20(%sp),%sp
 bra.s project_deserialize_done
project_deserialize_fail:
 moveq #0,%d2
project_deserialize_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a5
 lea 20(%sp),%sp
 rts

/* (serialized destination, raw source, argument3, flags, callback). */
sample_project_serialize:
 lea -20(%sp),%sp
 movem.l %d2/%a2-%a5,(%sp)
 move.l 24(%sp),%a2
 move.l 28(%sp),%a3
 suba.l %a4,%a4
 suba.l %a5,%a5
 move.l 0x446478d0,%d0
 beq.w project_serialize_native
 move.l %d0,%a0
 cmp.l 16(%a0),%a3
 bne.w project_serialize_native
 move.l %a2,-(%sp)
 jsr sample_project_serial_entry
 addq.l #4,%sp
 move.l %d0,%a5
 tst.l %d0
 beq.s project_serialize_native
 move.l PROJECT_STATE,%d0
 beq.w project_serialize_fail
 move.l %d0,%a4
 tst.l 4(%a4)
 beq.w project_serialize_fail
 cmp.l 12(%a4),%a3
 bne.w project_serialize_fail
 clr.l 4(%a5)
project_serialize_native:
 move.l 40(%sp),-(%sp)
 move.l 40(%sp),-(%sp)
 move.l 40(%sp),-(%sp)
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 jsr NATIVE_SERIALIZE
 lea 20(%sp),%sp
 move.l %d0,%d2
 tst.l %a5
 beq.s project_serialize_done
 tst.b %d2
 beq.s project_serialize_done
 move.l #128,%d0
 cmpa.l #0x405cd96c,%a2
 beq.s project_serialize_publish
 move.l -12(%a2),%d0
project_serialize_publish:
 move.l %d0,-(%sp)
 move.l 24(%a2),-(%sp)
 move.l %a2,-(%sp)
 move.l %a4,-(%sp)
 move.l %a5,-(%sp)
 jsr sample_project_publish
 lea 20(%sp),%sp
 /* Native load regenerates UID; retain live owner while adopting new UID. */
 move.l 24(%a2),8(%a4)
 bra.s project_serialize_done
project_serialize_fail:
 moveq #0,%d2
project_serialize_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a5
 lea 20(%sp),%sp
 rts

/* Existing cache blank hook stays in use; add the active serialized mirror. */
sample_project_blank:
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 move.l 16(%sp),%a2
 move.l %a2,-(%sp)
 jsr CACHE_BLANK
 addq.l #4,%sp
 move.l %d0,%d2
 tst.b %d2
 beq.s project_blank_done
 cmpa.l #0x405cd96c,%a2
 bne.s project_blank_done
 move.l %a2,-(%sp)
 jsr sample_project_serial_entry
 addq.l #4,%sp
 tst.l %d0
 beq.s project_blank_fail
 move.l %d0,%a3
 move.l #128,-(%sp)
 move.l 24(%a2),-(%sp)
 move.l %a2,-(%sp)
 clr.l -(%sp)
 move.l %a3,-(%sp)
 jsr sample_project_publish
 lea 20(%sp),%sp
 bra.s project_blank_done
project_blank_fail:
 moveq #0,%d2
project_blank_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts

/* Read-only donor settings view: only +1D2 is dereferenced by the getter. */
sample_project_settings_raw:
 move.l 0x446478d0,%d0
 beq.s project_settings_none
 move.l %d0,%a0
 addi.l #0x30,%d0
 cmp.l 4(%sp),%d0
 bne.s project_settings_none
 move.l PROJECT_STATE,%d0
 beq.s project_settings_none
 move.l %d0,%a1
 tst.l 4(%a1)
 beq.s project_settings_none
 move.l 16(%a0),%d1
 cmp.l 12(%a1),%d1
 bne.s project_settings_none
 addi.l #0x3e,%d0
 rts
project_settings_none:
 moveq #0,%d0
 rts
