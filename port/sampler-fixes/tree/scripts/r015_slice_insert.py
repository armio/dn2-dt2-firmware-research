"""Keep an existing slice intact when the imported editor rejects its split."""
import struct


def apply(ctx):
    editor = int(ctx.doc['manual_slice_editor']['methods']['init'], 16)
    relocation = editor - 0x4001bcbe
    split_store = relocation + 0x4001b316
    insert = relocation + 0x4001b296
    reject = relocation + 0x4001b280

    # On this path D2 is the proposed midpoint, D3 the old endpoint, A0 the
    # current slice. The preceding native guard already requires D2 < D3.
    guard = ctx.append_asm('slice_split_guard', f'''.text
 move.l %d3,%d0
 sub.l %d2,%d0
 cmpi.l #144,%d0
 bcs.s too_short
 move.l %d2,12(%a0)
 jmp {insert:#x}
too_short:
 jmp {reject:#x}
''')
    original = bytes.fromhex('2142000c6000ff60')
    jump = bytes.fromhex('4ef9') + struct.pack('>I', guard) + bytes.fromhex('4e71')
    ctx.replace(split_store, original, jump)
    return dict(split_store=hex(split_store), guard=hex(guard),
                minimum_new_slice_frames=144)
