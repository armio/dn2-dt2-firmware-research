/* T1D3: record allocator evidence before reuse of the live Project block.
 * Active only through the first published Project's initial Kit reset.
 */
.text
.global boot_heap_project,boot_heap_bitmap,boot_heap_mask
.global boot_heap_free_caller,boot_heap_free_pointer,boot_heap_fault
boot_heap_project: .long 0
boot_heap_bitmap: .long 0
boot_heap_mask: .long 0
boot_heap_free_caller: .long 0
boot_heap_free_pointer: .long 0

.macro save_heap
 lea -20(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 move.w %sr,%d0
 move.l %d0,16(%sp)
 lea 20(%sp),%a1
.endm
.macro restore_heap
 move.l 16(%sp),%d0
 move.w %d0,%ccr
 movem.l (%sp),%d0-%d1/%a0-%a1
 lea 20(%sp),%sp
.endm

/* D0 reason, A1 native entry stack, A0 event pointer, D1 requested size.
 * Copy all evidence before native formatter; no allocations or recovery.
 */
boot_heap_trap:
 lea -48(%sp),%sp
 move.l %d0,4(%sp)
 move.l #0x54423344,%d0
 move.l %d0,(%sp)
 move.l boot_heap_project,%d0
 move.l %d0,8(%sp)
 move.l (%a1),%d0
 move.l %d0,12(%sp)
 move.l %a0,16(%sp)
 move.l %d1,20(%sp)
 move.l %d2,24(%sp)
 move.l boot_heap_bitmap,%a0
 mvz.b (%a0),%d0
 move.l %d0,28(%sp)
 move.l 0x4029eba8,%a0
 move.l 60(%a0),%d0
 move.l %d0,32(%sp)
 move.l 64(%a0),%d0
 move.l %d0,36(%sp)
 move.l boot_heap_free_caller,%d0
 move.l %d0,40(%sp)
 move.l boot_heap_free_pointer,%d0
 move.l %d0,44(%sp)
boot_heap_fault:
 .word 0x4afc
 bra.w boot_heap_fault

/* A1=original entry stack. Called only with watched Project known. */
boot_heap_bitcheck:
 move.l boot_heap_bitmap,%a0
 mvz.b (%a0),%d1
 and.l boot_heap_mask,%d1
 bne.w boot_heap_bit_ok
 move.l #0xb0,%d0
 move.l 4(%a1),%a0
 move.l 4(%a1),%d1
 bra.w boot_heap_trap
boot_heap_bit_ok:
 rts

.global boot_heap_project_allocated
boot_heap_project_allocated:
 save_heap
 move.l (%sp),%d0
 move.l %d0,boot_heap_project
 sub.l 0x4029eba0,%d0
 lsr.l #4,%d0
 addi.l #0x7fff,%d0 /* native Project request6E40C ->8000 allocation units */
 move.l %d0,%d1
 andi.l #7,%d1
 moveq #1,%d0
 lsl.l %d1,%d0
 move.l %d0,boot_heap_mask
 move.l (%sp),%d0
 sub.l 0x4029eba0,%d0
 lsr.l #4,%d0
 addi.l #0x7fff,%d0
 lsr.l #3,%d0
 add.l 0x4029eba4,%d0
 move.l %d0,boot_heap_bitmap
 clr.l boot_heap_free_caller
 clr.l boot_heap_free_pointer
 /* At this call site the allocation size is at(sp), not an entry frame.
  * Supply a synthetic entry stack so a failed initial mark has a real caller. */
 lea -8(%sp),%sp
 move.l #0x4018a99a,%d0
 move.l %d0,(%sp)
 move.l #0x6e40c,%d0
 move.l %d0,4(%sp)
 move.l %sp,%a1
 bsr.w boot_heap_bitcheck
 addq.l #8,%sp
 restore_heap
 move.l 0x405c6dd8,-(%sp)
 jmp 0x4018a9a0

.global boot_heap_malloc_enter
boot_heap_malloc_enter:
 save_heap
 tst.l boot_heap_project
 beq.w heap_malloc_enter_done
 tst.l WATCH_DONE
 bne.w heap_malloc_enter_done
 bsr.w boot_heap_bitcheck
heap_malloc_enter_done:
 restore_heap
 lea -44(%sp),%sp
 movem.l %d2-%d7/%a2-%a6,(%sp)
 jmp 0x4011fff0

.global boot_heap_free_enter
boot_heap_free_enter:
 save_heap
 tst.l boot_heap_project
 beq.w heap_free_enter_done
 tst.l WATCH_DONE
 bne.w heap_free_enter_done
 bsr.w boot_heap_bitcheck
 move.l 4(%a1),%a0
 cmpa.l boot_heap_project,%a0
 blo.w heap_free_record
 move.l boot_heap_project,%d0
 addi.l #0x80000,%d0
 cmp.l %a0,%d0
 bls.w heap_free_record
 move.l 4(%a1),%d1
 move.l #0xf0,%d0
 bra.w boot_heap_trap
heap_free_record:
 move.l (%a1),%d0
 move.l %d0,boot_heap_free_caller
 move.l %a0,boot_heap_free_pointer
heap_free_enter_done:
 restore_heap
 lea -12(%sp),%sp
 movem.l %d2-%d4,(%sp)
 jmp 0x401201f6

.global boot_heap_malloc_return
boot_heap_malloc_return:
 save_heap
 lea 64(%sp),%a1 /*20 saved +44 native frame = entry SP */
 tst.l boot_heap_project
 beq.w heap_malloc_return_done
 tst.l WATCH_DONE
 bne.w heap_malloc_return_done
 bsr.w boot_heap_bitcheck
 move.l (%sp),%a0 /* actual returned pointer, before native MOVEM */
 tst.l %a0
 beq.w heap_malloc_return_done
 move.l boot_heap_project,%d0
 addi.l #0x80000,%d0
 cmp.l %a0,%d0
 bls.w heap_malloc_return_done
 move.l %d2,%d1 /* native allocated units */
 lsl.l #4,%d1
 add.l %a0,%d1
 cmp.l boot_heap_project,%d1
 bls.w heap_malloc_return_done
 move.l 4(%a1),%d1
 move.l #0xa0,%d0
 bra.w boot_heap_trap
heap_malloc_return_done:
 restore_heap
 movem.l (%sp),%d2-%d7/%a2-%a6
 lea 44(%sp),%sp
 jmp 0x401201ba
.balign 4
