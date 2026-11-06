"""Use each selected Sound's sampler parameter and native encoder response."""
import struct

# Factory allocation includes its 16-byte shared owner. Append one pointer to
# the synchronous event frame, a membership mask, and 6*8 native 20-byte knob
# states. Every Source instance owns its residuals and frees them with the view.
VT = 0x47a9bee0
CONTEXT = 0x268
LAST_MASK = CONTEXT + 4
STATES = LAST_MASK + 4
EXTRA = 8 + 6*8*20
BE = lambda value: struct.pack('>I', value)


def apply(ctx):
    allocate = ctx.append_asm('held-source-allocate', f""".text
        pea {0x278+EXTRA}
        jsr 0x40120264
        addq.l #4,%sp
        tst.l %d0
        beq.s done
        movea.l %d0,%a0
        lea 0x278(%a0),%a0
        move.l #{EXTRA//4},%d1
    zero_tail:
        clr.l (%a0)+
        subq.l #1,%d1
        bne.s zero_tail
    done:
        rts
    """)
    # Frame layout: page, event, mask, active flag, step[128], six (ID,delta)
    # pairs. Restoring the previous pointer also handles synchronous reentry.
    dispatch = ctx.append_asm('held-source-dispatch', f""".text
        link.w %a6,#-196
        move.l %a2,-(%sp)
        move.l %a3,-(%sp)
        movea.l 8(%a6),%a2
        lea -192(%a6),%a3
        move.l {CONTEXT}(%a2),-196(%a6)
        move.l %a3,{CONTEXT}(%a2)
        move.l %a2,(%a3)
        move.l 12(%a6),4(%a3)
        clr.l 8(%a3)
        clr.l 12(%a3)
        move.l 12(%a6),-(%sp)
        move.l %a2,-(%sp)
        jsr 0x40067470
        addq.l #8,%sp
        move.l -196(%a6),{CONTEXT}(%a2)
        movea.l (%sp)+,%a3
        movea.l (%sp)+,%a2
        unlk %a6
        rts
    """)
    collect = ctx.append_asm('held-trig-machine', """
        .text
        link.w %a6,#-16
        movem.l %d2-%d3/%a2-%a3,(%sp)
        movea.l 8(%a6),%a0
        movea.l (%a0),%a3
        movea.l (%a3),%a2
        move.l 12(%a6),%d2
        cmpi.l #127,%d2
        bhi.w done
        movea.l (%a2),%a0
        movea.l 0xa4(%a0),%a0
        move.l %d2,-(%sp)
        move.l %a2,-(%sp)
        jsr (%a0)
        addq.l #8,%sp
        move.l %d0,%d3
        cmpi.l #127,%d3
        bhi.s live
        movea.l 0x68(%a2),%a0
        adda.l #0x4f358,%a0
        movea.l (%a0),%a1
        move.l %d3,-(%sp)
        move.l %a0,-(%sp)
        movea.l 0x68(%a1),%a1
        jsr (%a1)
        addq.l #8,%sp
        tst.b %d0
        beq.s invalid
        move.l %d3,-(%sp)
        move.l 0x68(%a2),-(%sp)
        jsr 0x4003e426
        addq.l #8,%sp
        bra.s machine
    live:
        move.l 0x74(%a2),-(%sp)
        jsr 0x40046bfe
        move.l %d0,-(%sp)
        move.l 0x78(%a2),-(%sp)
        jsr 0x40030e66
        lea 12(%sp),%sp
    machine:
        tst.l %d0
        beq.s invalid
        move.l %d0,-(%sp)
        jsr 0x4004b7f2
        addq.l #4,%sp
        subi.l #5,%d0
        cmpi.l #5,%d0
        bls.s store
    invalid:
        moveq #6,%d0
    store:
        move.b %d0,16(%a3,%d2.l)
        move.l 8(%a3),%d1
        bset %d0,%d1
        move.l %d1,8(%a3)
    done:
        movem.l (%sp),%d2-%d3/%a2-%a3
        unlk %a6
        rts
    """)
    scale = ctx.append_asm('held-encoder-scale', f""".text
        /* Call site 400675be has a2=page, d2=resolved ID, d3=knob. */
        move.l (%a2),%d0
        cmpi.l #{VT},%d0
        bne.w native
        cmpi.l #7,%d3
        bhi.w native
        movea.l {CONTEXT}(%a2),%a0
        tst.l %a0
        beq.w native
        link.w %a6,#-80
        movem.l %d2-%d7/%a2-%a5,(%sp)
        movea.l %a0,%a3
        move.l %d2,-36(%a6)
        move.l %d3,-32(%a6)
        move.l 0x6c(%a2),-(%sp)
        jsr 0x400563e2
        addq.l #4,%sp
        tst.b %d0
        beq.w unmixed
        /* Only the ordinary held-trig route consumes these deltas. */
        pea 16
        jsr 0x4011f7e4
        addq.l #4,%sp
        tst.l %d0
        bne.w unmixed
        pea 22
        jsr 0x4011f7e4
        addq.l #4,%sp
        tst.l %d0
        bne.w unmixed
        move.l %a3,-28(%a6)
        clr.l -24(%a6)
        moveq #1,%d0
        move.l %d0,-20(%a6)
        move.l #{collect},%d0
        move.l %d0,-16(%a6)
        clr.l -(%sp)
        pea -28(%a6)
        move.l 0x6c(%a2),-(%sp)
        jsr 0x40056926
        lea 12(%sp),%sp
        move.l 8(%a3),%d0
        move.l %d0,%d1
        subq.l #1,%d1
        and.l %d0,%d1
        beq.w unmixed
        cmp.l {LAST_MASK}(%a2),%d0
        beq.s ready
        move.l %d0,{LAST_MASK}(%a2)
        lea {STATES}(%a2),%a0
        move.l #240,%d1
    reset_states:
        clr.l (%a0)+
        subq.l #1,%d1
        bne.s reset_states
    ready:
        moveq #1,%d0
        move.l %d0,12(%a3)
        moveq #0,%d4
        moveq #0,%d5
        moveq #0,%d6
        lea 144(%a3),%a4
    each_machine:
        clr.l (%a4)
        clr.l 4(%a4)
        move.l 8(%a3),%d0
        btst %d4,%d0
        beq.w advance
        moveq #5,%d0
        add.l %d4,%d0
        move.l %d0,-(%sp)
        jsr 0x400c248e
        addq.l #4,%sp
        movea.l %d0,%a0
        move.l -32(%a6),%d3
        move.l 8(%a0,%d3.l*4),%d7
        beq.w advance
        cmpi.l #10,%d7
        beq.w advance
        move.l %d7,(%a4)
        move.l %d7,-(%sp)
        jsr 0x400c2418
        addq.l #4,%sp
        movea.l %d0,%a5
        move.l 8(%a5),-(%sp)
        move.l 4(%a5),-(%sp)
        move.l 4(%a3),-(%sp)
        jsr 0x4011313e
        lea 12(%sp),%sp
        move.l %d4,%d1
        lsl.l #2,%d1
        add.l %d4,%d1
        lsl.l #5,%d1
        lea {STATES-20}(%a2),%a0
        adda.l %d1,%a0
        move.l 24(%a6),-(%sp)
        move.l 16(%a5),-(%sp)
        move.l %d0,-(%sp)
        move.l %d3,-(%sp)
        move.l %a0,-(%sp)
        jsr 0x4011336e
        lea 20(%sp),%sp
        move.l %d0,4(%a4)
        or.l %d0,%d6
        cmp.l -36(%a6),%d7
        bne.s advance
        move.l %d0,%d5
    advance:
        addq.l #8,%a4
        addq.l #1,%d4
        cmpi.l #6,%d4
        bne.w each_machine
        move.l %d5,%d0
        bne.s finish
        tst.l %d6
        beq.s finish
        moveq #1,%d0
    finish:
        movem.l (%sp),%d2-%d7/%a2-%a5
        unlk %a6
        rts
    unmixed:
        clr.l {LAST_MASK}(%a2)
        movem.l (%sp),%d2-%d7/%a2-%a5
        unlk %a6
    native:
        jmp 0x4011336e
    """)
    callback = ctx.append_asm('held-target-parameter', f""".text
        movea.l 4(%sp),%a0
        movea.l (%a0),%a1
        movea.l (%a1),%a0
        move.l (%a0),%d0
        cmpi.l #{VT},%d0
        bne.s native
        movea.l {CONTEXT}(%a0),%a1
        tst.l %a1
        beq.s native
        tst.l 12(%a1)
        beq.s native
        move.l 8(%sp),%d0
        cmpi.l #127,%d0
        bhi.s skip
        mvz.b 16(%a1,%d0.l),%d1
        cmpi.l #5,%d1
        bhi.s skip
        lsl.l #3,%d1
        lea 144(%a1),%a1
        adda.l %d1,%a1
        tst.l (%a1)
        beq.s skip
        tst.l 4(%a1)
        beq.s skip
        link.w %a6,#-16
        /* Local capture gives the original callback its own page, ID, delta.
           No shared selection/capture mutation during external notifications. */
        move.l %a0,-12(%a6)
        move.l (%a1),-8(%a6)
        move.l 4(%a1),-4(%a6)
        lea -12(%a6),%a0
        move.l %a0,-16(%a6)
        move.l 16(%a6),-(%sp)
        move.l 12(%a6),-(%sp)
        pea -16(%a6)
        jsr 0x40064d08
        lea 12(%sp),%sp
        unlk %a6
    skip:
        rts
    native:
        jmp 0x40064d08
    """)
    ctx.replace(0x47a9c958, BE(0x40120264), BE(allocate))
    ctx.replace(0x47a948f8, BE(0x40067470), BE(dispatch))
    ctx.replace(0x400675c0, BE(0x4011336e), BE(scale))
    ctx.replace(0x40065074, BE(0x40064d08), BE(callback))
    return dict(allocation=hex(allocate), dispatch=hex(dispatch), collect=hex(collect),
                scale=hex(scale), callback=hex(callback), extra_source_heap_bytes=EXTRA,
                native_callback='0x40064d08', native_scaler='0x4011336e',
                semantics='Resolve each selected trig to its effective Sound and apply each sampler Machine’s own encoder and lock semantics.')
