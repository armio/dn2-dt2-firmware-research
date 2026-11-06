"""Stage replacement PCM under the loader mutex before retiring the target slot."""
import struct


# Every bank's first slot is OFF (native and DSP project indices are 0..1023).
# H:OFF can own a temporary allocator record, but must never reach the DSP/UI.
STAGE = 7 * 128
CORE = 0x47aa4a3c
UNLOAD = 0x47a76e7c
IDENTITIES = 0x47a77100
LENGTHS = 0x47a614a0
NAMES = 0x47a604a0
NAME_BUFFERS = 0x47a7c100


def apply(ctx):
    def redirect(address, expected, target, call=False):
        old = bytes.fromhex(expected)
        opcode = b'\x4e\xb9' if call else b'\x4e\xf9'
        ctx.replace(address, old, opcode + struct.pack('>I', target) + b'\x4e\x71' * ((len(old) - 6) // 2))

    # Protected by the existing recursive sample mutex: positive during staging,
    # negative after the destination descriptor has been acknowledged, zero idle.
    phase = ctx.append_asm('sample_replace_slot', '.text\n.long 0\n')

    # This entry is reached after the public loader acquired the sample mutex.
    # Call its native core directly for staging, then for the actual slot. Only
    # the private call site can bypass H:OFF's normal rejection. The descriptor
    # and event gates below keep the staging owner out of project-visible I/O.
    transaction = ctx.append_asm('sample_replace_transaction', f""".text
 bra.w replace
 bra.w slot_gate
replace:
 move.l 8(%sp),%d0
 cmpi.l #1023,%d0
 bhi.w ordinary
 moveq #127,%d1
 and.l %d0,%d1
 beq.w ordinary
 lea {LENGTHS:#x},%a0
 tst.l (%a0,%d0.l*4)
 beq.w ordinary
 move.l 4(%sp),%a1
 tst.l %a1
 beq.w ordinary
 lsl.l #4,%d0
 lea {IDENTITIES:#x},%a0
 pea (%a0,%d0.l)
 move.l %a1,-(%sp)
 jsr 0x47a76408
 addq.l #8,%sp
 tst.l %d0
 bne.w ordinary
 tst.l {LENGTHS + STAGE*4:#x}
 bne.w reject
 move.l 8(%sp),%d0
 move.l %d0,{phase:#x}
 pea {STAGE}
 move.l 8(%sp),-(%sp)
 jsr {CORE:#x}
stage_return:
 addq.l #8,%sp
 tst.l %d0
 bne.s stage_failed
 move.l 8(%sp),-(%sp)
 move.l 8(%sp),-(%sp)
 jsr {CORE:#x}
 addq.l #8,%sp
 move.l %d0,-(%sp)
 pea {STAGE}
 jsr {UNLOAD:#x}
 addq.l #4,%sp
 move.l (%sp)+,%d0
 clr.l {phase:#x}
 rts
stage_failed:
 clr.l {phase:#x}
 moveq #-1,%d0
 rts
ordinary:
 jmp {CORE:#x}
reject:
 moveq #-1,%d0
 rts
slot_gate:
 moveq #127,%d0
 and.l %d2,%d0
 bne.s valid
 cmpi.l #{STAGE},%d2
 bne.s invalid
 lea stage_return(%pc),%a0
 cmpa.l 4(%a6),%a0
 bne.s invalid
valid:
 jmp 0x47a76672
invalid:
 jmp 0x47a76876
""")
    redirect(0x47aa4a1c, '4eb9 47aa4a3c', transaction, call=True)
    redirect(0x47a7666a, '707f c082 6700 0206', transaction + 4)

    # The native sharing branch attaches the staged block to the real slot
    # without reopening or rereading it. Recheck resolved object identities:
    # a filesystem race aborts before the old slot unloads. Publish the new
    # descriptor before retiring the old owner. On ambiguous transport failure
    # the existing sticky gate blocks every later PCM upload until reboot.
    commit = ctx.append_asm('sample_replace_commit', f""".text
 cmp.l {phase:#x},%d2
 bne.w ordinary
 tst.l {LENGTHS + STAGE*4:#x}
 beq.w changed
 pea {IDENTITIES + STAGE*16:#x}
 move.l %d4,-(%sp)
 jsr 0x47a76408
 addq.l #8,%sp
 tst.l %d0
 beq.w changed
 move.l {0x47a7b100+4*STAGE:#x},%d0
 cmpi.l #1023,%d0
 bhi.w changed
 moveq #52,%d1
 muls.l %d1,%d0
 move.l 0x47a763fc,%a0
 adda.l %d0,%a0
 cmpa.l 0x47a76400,%a0
 bcc.w changed
 move.l 16(%a0),%a1
 move.l {0x47a80500+4*STAGE:#x},%d0
 move.l %d0,-(%sp)
 move.l {LENGTHS+4*STAGE:#x},%d0
 move.l %d0,-(%sp)
 tst.b {0x47a80100+STAGE:#x}
 beq.s mono
 move.l 20(%a0),%d0
 lsr.l #1,%d0
 lea 32(%a1),%a1
 pea (%a1,%d0.l)
 move.l %a1,-(%sp)
 move.l %d2,-(%sp)
 jsr 0x47a760c0
 lea 20(%sp),%sp
 bra.s acknowledged
mono:
 pea 64(%a1)
 move.l %d2,-(%sp)
 jsr 0x47a76128
 lea 16(%sp),%sp
acknowledged:
 tst.l 0x47aa5a10
 bne.s changed
 move.l %d2,%d0
 neg.l %d0
 move.l %d0,{phase:#x}
 jmp 0x47acdc3e
ordinary:
 jmp 0x47acdbc8
changed:
 jmp 0x47a76876
""")
    redirect(0x47a766c2, '4ef9 47acdbc8', commit)

    # Shared owners need independent labels: the donor copies the source's
    # name pointer and overwrites that buffer when its original slot is reused.
    name_copy = ctx.append_asm('sample_own_shared_name', f""".text
 move.l (%a0,%d4.l*4),%a1
 move.l %d2,%d0
 lsl.l #4,%d0
 addi.l #{NAME_BUFFERS:#x},%d0
 move.l %d0,(%a0,%d2.l*4)
 move.l %d0,%a0
 move.l (%a1)+,(%a0)+
 move.l (%a1)+,(%a0)+
 move.l (%a1)+,(%a0)+
 move.l (%a1),(%a0)
 jmp 0x47a7680a
""")
    redirect(0x47a76802, '43f0 4c00 2191 2c00', name_copy)

    for address, name, expected in ((0x47a760c0, 'stereo', '598f 2f0e 48781000'),
                                    (0x47a76128, 'mono', '598f 2f0e 48781000')):
        gate = ctx.append_asm('sample_replace_descriptor_' + name, f""".text
 move.l {phase:#x},%d0
 beq.s publish
 move.l 4(%sp),%d1
 cmpi.l #{STAGE},%d1
 beq.s skip
 neg.l %d0
 cmp.l %d1,%d0
 beq.s skip
publish:
 subq.l #4,%sp
 move.l %a6,-(%sp)
 pea 4096
 jmp {address+8:#x}
skip:
 rts
""")
        redirect(address, expected, gate)
    notify = ctx.append_asm('sample_replace_notification', f""".text
 tst.l {phase:#x}
 beq.s emit
 move.l 8(%sp),%d0
 cmpi.l #{STAGE},%d0
 bne.s emit
 move.l 4(%sp),%d0
 cmpi.l #31,%d0
 beq.s skip
 cmpi.l #32,%d0
 beq.s skip
emit:
 move.l 0x47a85500,%d0
 jmp 0x47a85cae
skip:
 rts
""")
    redirect(0x47a85ca8, '2039 47a85500', notify)
    return dict(transaction=hex(transaction), staging_owner=STAGE, commit=hex(commit),
                loader_mutex='0x47a9d99c')
