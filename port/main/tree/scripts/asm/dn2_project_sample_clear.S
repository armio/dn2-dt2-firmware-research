/* Native raw Project reset: used by NEW PROJECT and cold-start fallback.
 * The raw initializer returns void; preserve its return register without
 * interpreting it as a success flag. Its null-input path is also preserved.
 */
.text
.global sample_project_raw_clear
sample_project_raw_clear:
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 move.l 16(%sp),%a2
 suba.l %a3,%a3
 tst.l %a2
 beq.s raw_clear_native
 move.l 0x446478d0,%d0
 beq.s raw_clear_boot_owner
 move.l %d0,%a0
 cmp.l 16(%a0),%a2
 bne.s raw_clear_native
 bra.s raw_clear_owned
raw_clear_boot_owner:
 /* Native boot400BB25C initializes this fixed raw buffer before Project exists. */
 cmpa.l #0x41218970,%a2
 bne.s raw_clear_native
raw_clear_owned:
 jsr PROJECT_STATE
 move.l %d0,%a3
 tst.l %d0
 beq.s raw_clear_native
 /* Hide old identities before native initialization modifies raw memory. */
 clr.l 4(%a3)
raw_clear_native:
 move.l %a2,-(%sp)
 jsr NATIVE_RAW_CLEAR
 addq.l #4,%sp
 move.l %d0,%d2
 tst.l %a3
 beq.s raw_clear_done
 move.l #128,-(%sp)
 move.l 8(%a2),-(%sp)
 move.l %a2,-(%sp)
 clr.l -(%sp)
 move.l %a3,-(%sp)
 jsr PROJECT_PUBLISH
 lea 20(%sp),%sp
raw_clear_done:
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts
