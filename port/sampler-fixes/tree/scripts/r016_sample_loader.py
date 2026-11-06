"""Validate native PCM16 extents and close or roll back each failed sample read."""
import struct

# Allocator rounds (file_size + 0x200f) down to 8 KiB within its 400 MiB pool.
MAX_FILE_BYTES = 0x19000000 - 16
READ = 0x47a36246
OPEN = 0x47a858d0
SIZE = 0x47a3682e
CLOSE = 0x47a3644c
FAIL = 0x47a76876
# This existing R015 rollback closes the reader, frees both chunk buffers,
# unlinks the partial allocation and clears its DSP descriptor.
ROLLBACK = 0x47aa59e4


def apply(ctx):
    def hook(address, before_hex, target, call=False):
        before = bytes.fromhex(before_hex)
        instruction = b'\x4e\xb9' if call else b'\x4e\xf9'
        patch = instruction + struct.pack('>I', target) + b'\x4e\x71' * ((len(before)-6)//2)
        ctx.replace(address, before, patch)

    # A0 points to a complete 64-byte header. D0 is the stored object size,
    # including the 16-byte filesystem trailer. Avoid arithmetic on lengths
    # until the measured extent is within the allocator's representable range.
    header = ctx.append_asm('sample_header_valid', f""".text
 cmpi.l #82,%d0
 bcs.s invalid
 cmpi.l #{MAX_FILE_BYTES},%d0
 bhi.s invalid
 subi.l #80,%d0
 cmp.l 4(%a0),%d0
 bne.s invalid
 moveq #0,%d1
 move.b 1(%a0),%d1
 cmpi.l #1,%d1
 bhi.s invalid
 add.l %d1,%d1
 addq.l #1,%d1
 and.l %d1,%d0
 bne.s invalid
 move.l 8(%a0),%d0
 beq.s invalid
 moveq #1,%d0
 rts
invalid:
 moveq #0,%d0
 rts
""")
    # Small positive reads are legal. Assemble one entire requested native block
    # before the mono copier or stereo splitter receives any bytes.
    exact = ctx.append_asm('sample_read_exact', f""".text
 lea -16(%sp),%sp
 movem.l %d2-%d3/%a2-%a3,(%sp)
 move.l %a0,%a2
 move.l %a1,%a3
 move.l %d0,%d2
 move.l %d0,%d3
read_more:
 move.l %a3,-(%sp)
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 jsr {READ:#x}
 lea 12(%sp),%sp
 tst.l %d0
 ble.s failed
 cmp.l %d2,%d0
 bhi.s failed
 add.l %d0,%a2
 sub.l %d0,%d2
 bne.s read_more
 move.l %d3,%d0
 bra.s done
failed:
 moveq #-1,%d0
done:
 movem.l (%sp),%d2-%d3/%a2-%a3
 lea 16(%sp),%sp
 rts
""")
    # Same-identity loads already returned. New loads into an empty slot retain
    # the single-open path. Preflight a replacement before releasing its owner.
    # Reindex clears unused index entries to zero, also a valid record index.
    # The published byte length reliably distinguishes live slots.
    replacement = ctx.append_asm('sample_check_replacement', f""".text
 lea 0x47a614a0,%a0
 tst.l (%a0,%d2.l*4)
 beq.w unload
 lea -84(%sp),%sp
 pea 64(%sp)
 move.l %d4,-(%sp)
 jsr {OPEN:#x}
 addq.l #8,%sp
 tst.l %d0
 bmi.s reject_unopened
 move.l 64(%sp),-(%sp)
 jsr {SIZE:#x}
 addq.l #4,%sp
 cmp.l -124(%a6),%d0
 bne.s reject_open
 move.l %d0,80(%sp)
 lea 64(%sp),%a1
 move.l %sp,%a0
 moveq #64,%d0
 jsr {exact:#x}
 tst.l %d0
 bmi.s reject_open
 move.l %sp,%a0
 move.l 80(%sp),%d0
 jsr {header:#x}
 bra.s close
reject_open:
 moveq #0,%d0
close:
 move.l %d0,80(%sp)
 pea 64(%sp)
 jsr {CLOSE:#x}
 addq.l #4,%sp
 tst.l 80(%sp)
 beq.s reject_unopened
 lea 84(%sp),%sp
unload:
 move.l %d2,-(%sp)
 jsr 0x47a76dfc
 jmp 0x47a766c8
reject_unopened:
 lea 84(%sp),%sp
 jmp {FAIL:#x}
""")
    hook(0x47a766c2, '2f02 4eba0736', replacement)

    close_only = ctx.append_asm('sample_close_unallocated', f""".text
 pea -148(%a6)
 jsr {CLOSE:#x}
 addq.l #4,%sp
 jmp {FAIL:#x}
""")
    size = ctx.append_asm('sample_check_measured_size', f""".text
 addq.l #4,%sp
 cmpi.l #82,%d0
 bcs.s invalid
 cmpi.l #{MAX_FILE_BYTES},%d0
 bhi.s invalid
 cmp.l -124(%a6),%d0
 bne.s invalid
 move.l 0x47a763fc,%a2
 jmp 0x47a7688e
invalid:
 jmp {close_only:#x}
""")
    hook(0x47a76886, '247947a763fc 588f', size)
    allocation = ctx.append_asm('sample_check_allocation', f""".text
 tst.b %d0
 beq.s failed
 jmp 0x47a769ee
failed:
 jmp {close_only:#x}
""")
    hook(0x47a769e8, '4a00 6700fe8a', allocation)
    assigned = ctx.append_asm('sample_check_allocated_base', f""".text
 tst.l %a2
 bne.s allocated
 move.l %d2,-(%sp)
 jsr 0x47a76e7c
 addq.l #4,%sp
 jmp {close_only:#x}
allocated:
 jmp 0x47a76b2c
""")
    hook(0x47a76b26, '4a8a 6700fd4c', assigned)

    first = ctx.append_asm('sample_check_first_chunk', f""".text
 move.l (%sp),%a0
 tst.l %a0
 beq.s rejected
 tst.l -152(%a6)
 beq.s rejected
 move.l 8(%sp),%a1
 move.l -168(%a6),%d0
 cmp.l 4(%sp),%d0
 bls.s read
 move.l 4(%sp),%d0
read:
 jsr {exact:#x}
 cmpi.l #64,%d0
 blt.s rejected
 move.l %d0,%d7
 move.l (%sp),%a0
 move.l -168(%a6),%d0
 jsr {header:#x}
 tst.l %d0
 beq.s rejected
 move.l %d7,%d0
 jmp 0x47a76b60
rejected:
 lea 20(%sp),%sp
 jmp {ROLLBACK:#x}
""")
    hook(0x47a76b5a, '4eb947a36246', first)
    next_chunk = ctx.append_asm('sample_read_next_chunk', f""".text
 move.l 4(%sp),%a0
 move.l 12(%sp),%a1
 move.l -168(%a6),%d0
 sub.l %d7,%d0
 cmp.l 8(%sp),%d0
 bls.s read
 move.l 8(%sp),%d0
read:
 jmp {exact:#x}
""")
    hook(0x47a76bec, '4eb947a36246', next_chunk, call=True)
    hook(0x47a76bfc, '486eff68 45f947a76184', ROLLBACK)
    return dict(header=hex(header), read_exact=hex(exact), replacement=hex(replacement),
                first_chunk=hex(first), next_chunk=hex(next_chunk), rollback=hex(ROLLBACK),
                maximum_native_file_bytes=MAX_FILE_BYTES, rate_format='positive unsigned 32-bit Hz')
