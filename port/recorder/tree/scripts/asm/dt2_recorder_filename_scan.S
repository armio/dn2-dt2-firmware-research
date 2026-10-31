/* SamplerView's sole sscanf use: (name, "REC%04d", int*).
 * scanf width counts sign/digits but excludes preceding whitespace.
 * The remaining filename suffix is deliberately accepted, as in DT2.
 */
.text
.global recorder_filename_scan
recorder_filename_scan:
 move.l %d2,-(%sp)
 move.l %d3,-(%sp)
 move.l %d4,-(%sp)
 movea.l 16(%sp),%a0
 movea.l 24(%sp),%a1
 moveq #0,%d0
 move.b (%a0)+,%d1
 cmpi.b #'R',%d1
 bne.w done
 move.b (%a0)+,%d1
 cmpi.b #'E',%d1
 bne.w done
 move.b (%a0)+,%d1
 cmpi.b #'C',%d1
 bne.w done
space:
 move.b (%a0),%d1
 cmpi.b #32,%d1
 beq.s skip_space
 cmpi.b #9,%d1
 blo.s sign
 cmpi.b #13,%d1
 bhi.s sign
skip_space:
 addq.l #1,%a0
 bra.s space
sign:
 moveq #4,%d2
 moveq #0,%d3
 cmpi.b #'-',%d1
 bne.s plus
 moveq #1,%d3
 bra.s skip_sign
plus:
 cmpi.b #'+',%d1
 bne.s first
skip_sign:
 addq.l #1,%a0
 subq.l #1,%d2
first:
 mvz.b (%a0),%d1
 subi.l #48,%d1
 cmpi.l #9,%d1
 bhi.s done
digit:
 moveq #10,%d4
 mulu.l %d4,%d0
 add.l %d1,%d0
 addq.l #1,%a0
 subq.l #1,%d2
 beq.s store
 mvz.b (%a0),%d1
 subi.l #48,%d1
 cmpi.l #9,%d1
 bls.s digit
store:
 tst.l %d3
 beq.s positive
 neg.l %d0
positive:
 move.l %d0,(%a1)
 moveq #1,%d0
done:
 move.l (%sp)+,%d4
 move.l (%sp)+,%d3
 move.l (%sp)+,%d2
 rts
.balign 4
