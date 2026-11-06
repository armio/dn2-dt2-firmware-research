"""Commit Recorder's SAMP selection only after the pool-load worker succeeds."""
import struct


def apply(ctx):
    operand = next(edit for edit in ctx.doc['recorder_ui']['edits']
                   if edit['donor'] == '0x40019320' and edit['target'] == '0x4003b570')
    commit = int(operand['runtime'], 16) - 2
    setter = int(operand['binding'], 16)
    # At the setter call the completion has reserved 0x30 bytes of locals
    # and pushed 0x28 bytes of arguments. Its second argument, the pool
    # load status, is at 8 + 0x30 + 0x28 + 4 (this helper's return PC).
    guard = ctx.append_asm('recorder_assignment_status', f'''.text
 tst.l 0x64(%sp)
 bne.s failed
 jmp {setter:#x}
failed:
 rts
''')
    ctx.replace(commit, b'\x4e\xb9' + struct.pack('>I', setter),
                b'\x4e\xb9' + struct.pack('>I', guard))
    return dict(commit=hex(commit), setter=hex(setter), guard=hex(guard))
