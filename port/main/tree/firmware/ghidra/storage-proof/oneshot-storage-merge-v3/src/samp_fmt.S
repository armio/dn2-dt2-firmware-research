| M3a (rev 2): DT2-donor-shaped SAMP name formatter, stock-ABI-faithful.
| ABI learned from the stock formatter it replaces (0x400E31D0): args are
| (value at sp+4, arg2, buffer at sp+12); the callee must preserve ALL
| registers (the stock one uses only the stack). Rev 1 crashed (V03) by
| clobbering d0/d1/a1 and writing arg2 instead of arg3.
| Donor shape (DT2 1.16 0x400164E0): clamp vs pool count, resolve slot name,
| copy to buffer, donor OFF fallback. Data source: live bank directory at
| 0x47A3A000 + a baked 8-byte-entry name table.
.equ BANK_DIR, 0x47A3A000
samp_fmt:
    move.l  %d0, -(%sp)
    move.l  %d1, -(%sp)
    move.l  %a0, -(%sp)
    move.l  %a1, -(%sp)               | 16 bytes saved; args shift by 16
    move.l  20(%sp), %d0              | arg1: raw SAMP value (4+16)
    movea.l 28(%sp), %a0              | arg3: output buffer (12+16, stock offset)
    movea.l #BANK_DIR, %a1
    move.l  4(%a1), %d1               | live bank count
    cmp.l   %d1, %d0
    bhi.s   samp_off                  | value > count-1 -> donor OFF path
    move.l  %d0, %d1
    lsl.l   #3, %d1                   | 8-byte name entries
    lea     samp_names.l, %a1
    lea     (%a1, %d1.l), %a1
samp_copy:
    move.b  (%a1)+, (%a0)+
    bne.s   samp_copy
    move.l  (%sp)+, %a1
    move.l  (%sp)+, %a0
    move.l  (%sp)+, %d1
    move.l  (%sp)+, %d0
    rts
samp_off:
    lea     samp_offstr.l, %a1
    bra.s   samp_copy
.balign 4
samp_names:
    .ascii "SNARE\0\0\0"
    .ascii "BASS\0\0\0\0"
    .ascii "HI HAT\0\0"
samp_offstr:
    .ascii "OFF\0"
samp_empty:
    .ascii "---\0"
.balign 4
