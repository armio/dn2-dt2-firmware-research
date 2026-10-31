/* Native Save/copy-working-project uses one private temporary allocation.
 * Append its companion after the unchanged native serialized bytes. Native
 * conversion and writes keep their original lengths; native free owns both.
 */
.text
.global sample_snapshot_copy,sample_snapshot_serialize
sample_snapshot_copy:
 lea -20(%sp),%sp
 movem.l %d2-%d3/%a2-%a4,(%sp)
 movea.l 24(%sp),%a2
 movea.l 28(%sp),%a3
 move.l 32(%sp),%d3
 pea PROJECT_LOCK
 jsr 0x40001608
 addq.l #4,%sp
 move.l %d3,-(%sp)
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x40134490
 lea 12(%sp),%sp
 move.l %d0,%d2
 cmpi.l #0xc4b004,%d3
 bne.w copy_unlock
 cmpa.l #0x405cd96c,%a3
 bne.s copy_to_cache
 /* First copy: snapshot the separate working-project mirror table. */
 movea.l %a2,%a4
 adda.l #0xc4b004,%a4
 clr.l 4(%a4)
 move.l %a3,-(%sp)
 jsr SERIAL_ENTRY
 addq.l #4,%sp
 tst.l %d0
 beq.s copy_unlock
 movea.l %d0,%a0
 tst.l 4(%a0)
 beq.s copy_unlock
 move.l 24(%a3),%d0
 cmp.l 8(%a0),%d0
 bne.s copy_unlock
 cmp.l 12(%a0),%a3
 bne.s copy_unlock
 movea.l %a0,%a3
 move.l #128,%d3
 bra.s copy_publish
copy_to_cache:
 /* Second copy: the converter may have regenerated UID, but this allocation
  * still owns its independently captured sample table. Publish with new UID. */
 move.l %a2,-(%sp)
 jsr CACHE_ENTRY
 addq.l #4,%sp
 tst.l %d0
 beq.s copy_unlock
 movea.l %d0,%a4
 clr.l 4(%a4)
 movea.l %a3,%a0
 adda.l #0xc4b004,%a0
 tst.l 4(%a0)
 beq.s copy_unlock
 cmp.l 12(%a0),%a3
 bne.s copy_unlock
 movea.l %a0,%a3
 move.l -12(%a2),%d3
copy_publish:
 move.l %d3,-(%sp)
 move.l 24(%a2),-(%sp)
 move.l %a2,-(%sp)
 move.l %a3,-(%sp)
 move.l %a4,-(%sp)
 jsr PROJECT_PUBLISH
 lea 20(%sp),%sp
copy_unlock:
 pea PROJECT_LOCK
 jsr 0x4000172a
 addq.l #4,%sp
 move.l %d2,%d0
 movem.l (%sp),%d2-%d3/%a2-%a4
 lea 20(%sp),%sp
 rts

/* Keep the native serialized mirror and its table coherent with snapshot
 * readers and pool mutation. Power-off chunk I/O does not call this path. */
sample_snapshot_serialize:
 move.l %d2,-(%sp)
 pea PROJECT_LOCK
 jsr 0x40001608
 addq.l #4,%sp
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 jsr ORIGINAL_SERIALIZE
 lea 20(%sp),%sp
 move.l %d0,%d2
 pea PROJECT_LOCK
 jsr 0x4000172a
 addq.l #4,%sp
 move.l %d2,%d0
 move.l (%sp)+,%d2
 rts
.balign 4
