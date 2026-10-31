/* Replay the two instructions at40191768. Preserve successful native behavior.
 * On an invalid vtable/callee, place twelve diagnostic words on the stack for
 * the existing exception display and stop before dereferencing/calling it.
 */
.text
.global boot_kit_guard,boot_kit_fault
boot_kit_guard:
 move.l (%a2),%a0
 move.l %a0,%d0
 moveq #-1,%d1
 cmpi.l #0x40000400,%d0
 blo.w boot_kit_bad
 cmpi.l #0x48000000,%d0
 bhs.w boot_kit_bad
 move.l 0x6c(%a0),%d1
 cmpi.l #0x40000400,%d1
 blo.w boot_kit_bad
 cmpi.l #0x402fc000,%d1
 blo.s boot_kit_valid
 cmpi.l #0x46800000,%d1
 blo.w boot_kit_bad
 cmpi.l #0x47ab0000,%d1
 bhs.w boot_kit_bad
boot_kit_valid:
 move.l 0x5c(%a0),%a3
 jmp 0x4019176e

boot_kit_bad:
 lea -48(%sp),%sp
 move.l %a2,(%sp)
 move.l %a0,4(%sp)
 move.l %d1,8(%sp)
 move.l #0x54423144,%d0 /* TB1D diagnostic marker */
 move.l %d0,12(%sp)
 move.l 0x401da944,%d0
 move.l %d0,16(%sp)
 move.l 0x401da934,%d0
 move.l %d0,20(%sp)
 move.l 0x401916fe,%d0
 move.l %d0,24(%sp)
 move.l 0x446478d0,%d0
 move.l %d0,28(%sp)
 move.l 4(%a2),%d0
 move.l %d0,32(%sp)
 move.l 0x44(%a2),%d0
 move.l %d0,36(%sp)
 move.l 56(%sp),%d0 /* original native caller return address */
 move.l %d0,40(%sp)
 move.l #0x401da8d8,%d0
 move.l %d0,44(%sp)
boot_kit_fault:
 .word 0x4afc
 bra.w boot_kit_fault
.balign 4
