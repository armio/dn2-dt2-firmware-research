/* Called by the existing UI-task hook after native system startup. The
 * sample filesystem has private relocated BSS, outside the native clear.
 * Initialize and mount it once. No format, sample upload or bank load.
 */
.text
.global sample_fs_startup,sample_fs_status,sample_fs_result
sample_fs_startup:
 tst.l sample_fs_status
 bne.w fs_return
 moveq #1,%d0
 move.l %d0,sample_fs_status
 lea 0x46816f8c,%a0
 lea 0x47a19ca0,%a1
fs_clear_old:
 clr.l (%a0)+
 cmpa.l %a1,%a0
 bne.s fs_clear_old
 lea 0x47a1a000,%a0
 lea 0x47a35200,%a1
fs_clear_new:
 clr.l (%a0)+
 cmpa.l %a1,%a0
 bne.s fs_clear_new
 jsr fs_initialize
 moveq #1,%d0
 move.l %d0,0x47a19ca4
 pea 1.w
 jsr fs_mount
 addq.l #4,%sp
 move.l %d0,sample_fs_result
 tst.l %d0
 bne.s fs_failed
 move.l 0x46b9608c,%d0
 cmpi.l #1,%d0
 bne.s fs_failed
 moveq #2,%d0
 move.l %d0,sample_fs_status
 rts
fs_failed:
 moveq #-1,%d0
 move.l %d0,sample_fs_status
fs_return:
 rts
.balign 4
sample_fs_status:
 .long 0
sample_fs_result:
 .long -1
