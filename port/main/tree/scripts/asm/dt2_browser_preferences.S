/* SampleManager's AUTO-PREVIEW setter adapter. The donor getter remains
 * unchanged and uses the same relocated private byte. Persistence needs the
 * new browser preference store; do not call the donor whole-settings writer
 * against the DN2 settings block. */
.text
.global sample_auto_preview_set
sample_auto_preview_set:
 moveq #0,%d0
 tst.b 7(%sp)
 sne.b %d0
 neg.l %d0
 move.b %d0,0x4099d5d1
 rts
.balign 4
