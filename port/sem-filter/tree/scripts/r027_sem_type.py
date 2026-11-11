"""R027: SEM TYPE widget (docs/DN2-R027-SEM-TYPE-WIDGET-SPEC.md, option A).

The FILTER page draw computes the active filter at entry, with the same native calls its graph path makes, and
sets sem_type_flag while its body runs. Parameter ID 38's drawer reads the flag: clear, native; set, LP NOTCH HP
(native slider and marker), or the BP icon alone at TYPE 127.
"""
import hashlib
import re
import struct
import subprocess

import build_dt2_sampler_runtime as native

MAIN_BASE = 0x40000400
PAGE_DRAW, PAGE_BODY = 0x4006eabe, 0x4006eac6
PAGE_PROLOGUE = bytes.fromhex('4fefff9048d77cfc')     # lea -$70(a7),a7; movem.l d2-d7/a2-a6,(a7)
NATIVE_DRAWER, NATIVE_MARKER, INIT_IMMEDIATE = 0x400bd46e, 0x400bd49c, 0x400c3560
BLIT = 0x401157fc
BITMAP_VTABLE, PIXELS, MASK = 0x4020650c, 0x402d3fc4, 0x402d3f78
PIXELS_SHA = 'a564126b20a4665cadb8ce6045d530084bea982c4700c371262796886fd3e037'
MASK_SHA = '3f9584fca9d14c539b9a9e1c99ecfee36dd230a000973e69a94f7daea1cc164a'
COLUMNS, MIDDLE, ICON_ROWS = 19, range(7, 12), range(4, 9)
PLANES_SHA = '2e6c1d1abb22bb4213b6ddf64b7cad30e2cf190f7b5ac1dbcc3d5ff641c5d9c4'   # SEM + BP planes for OS 1.11


def bit(row):
    return 1 << (31-row)                                  # row 0 (the bar) is the most significant bit


def planes(words):
    """SEM plane: middle icon flipped vertically. BP plane: the middle icon alone."""
    sem, bp = list(words), [0]*COLUMNS
    for c in MIDDLE:
        keep = sum(words[c] & bit(r) for r in ICON_ROWS)
        flipped = sum(bit(12-r) for r in ICON_ROWS if words[c] & bit(r))
        sem[c] = words[c] & ~keep & 0xffffffff | flipped
        bp[c] = keep
    return sem, bp


def source(sem, bp):
    longs = lambda words: ','.join(f'{w:#010x}' for w in words)
    return f"""
 .text
 .globl sem_page_draw
/* FILTER page draw entry (jmp from {PAGE_DRAW:#x}): args view, canvas. */
sem_page_draw:
 lea -8(%sp),%sp
 movem.l %d2/%a2,(%sp)
 movea.l 12(%sp),%a2
 movea.l (%a2),%a0
 move.l %a2,-(%sp)
 movea.l 0x88(%a0),%a0
 jsr (%a0)
 addq.l #4,%sp
 moveq #12,%d1
 cmp.l %d0,%d1
 bne.w sem_page_run
 /* Same calls, order and arguments as the native graph path at 0x4006ec4a..0x4006ec9e. */
 move.l 0x74(%a2),-(%sp)
 jsr 0x40046bfe
 addq.l #4,%sp
 move.l %d0,%d2
 move.l 0x68(%a2),-(%sp)
 jsr 0x4003e41a
 move.l %d2,-(%sp)
 move.l %d0,-(%sp)
 jsr 0x400313a6
 move.l %a2,-(%sp)
 move.l %d0,%d2
 jsr 0x4006e9f2
 lea 16(%sp),%sp
 moveq #0x7f,%d1
 cmp.l %d0,%d1
 bcs.s sem_page_kind
 move.l %d0,-(%sp)
 move.l 0x68(%a2),-(%sp)
 jsr 0x4003e426
 move.l %d0,-(%sp)
 jsr 0x4004b860
 lea 12(%sp),%sp
 move.l %d0,%d2
sem_page_kind:
 moveq #6,%d1
 cmp.l %d2,%d1
 bne.s sem_page_run
 moveq #1,%d0
 move.b %d0,sem_type_flag
sem_page_run:
 movem.l (%sp),%d2/%a2
 lea 8(%sp),%sp
 move.l 8(%sp),-(%sp)
 move.l 8(%sp),-(%sp)
 jsr sem_page_body
 addq.l #8,%sp
 moveq #0,%d1
 move.b %d1,sem_type_flag
 rts
/* Replays the native page-draw prologue displaced by the entry jmp, then continues natively. */
sem_page_body:
 lea -0x70(%sp),%sp
 movem.l %d2-%d7/%a2-%a6,(%sp)
 jmp {PAGE_BODY:#x}

/* Parameter ID 38 drawer: args closure, value, canvas, x, y (native {NATIVE_DRAWER:#x}). */
sem_type_draw:
 tst.b (sem_type_flag).l
 bne.s sem_type_sem
 jmp {NATIVE_DRAWER:#x}
/* Same entry as the native drawer, so the jmp to its marker code below finds an identical frame. */
sem_type_sem:
 lea -0x10(%sp),%sp
 movem.l %d2-%d4/%a2,(%sp)
 movea.l 0x24(%sp),%a2
 move.l 0x18(%sp),%d4
 move.l 0x1c(%sp),%d2
 move.l 0x20(%sp),%d3
 clr.l -(%sp)
 pea 6(%a2)
 move.l %d3,-(%sp)
 move.l %d4,%d0
 asr.l #8,%d0
 moveq #127,%d1
 cmp.l %d0,%d1
 beq.s sem_type_bp
 pea sem_type_bitmap
 move.l %d2,-(%sp)
 jsr {BLIT:#x}
 jmp {NATIVE_MARKER:#x}
sem_type_bp:
 pea sem_type_bp_bitmap
 move.l %d2,-(%sp)
 jsr {BLIT:#x}
 lea 0x14(%sp),%sp
 movem.l (%sp),%d2-%d4/%a2
 lea 0x10(%sp),%sp
 rts

.balign 4
sem_type_bitmap: .long {BITMAP_VTABLE:#x},{COLUMNS},9,1,sem_type_plane,{MASK:#x},0
sem_type_bp_bitmap: .long {BITMAP_VTABLE:#x},{COLUMNS},9,1,sem_type_bp_plane,{MASK:#x},0
sem_type_plane: .long {longs(sem)}
sem_type_bp_plane: .long {longs(bp)}
sem_type_flag: .byte 0
.balign 4
"""


def read(ctx, address, size):
    return bytes(ctx.image[address-MAIN_BASE:address-MAIN_BASE+size])     # static MAIN, as ctx.replace maps it


def apply(ctx):
    pixels, mask = read(ctx, PIXELS, 4*COLUMNS), read(ctx, MASK, 4*COLUMNS)
    if (hashlib.sha256(pixels).hexdigest(), hashlib.sha256(mask).hexdigest()) != (PIXELS_SHA, MASK_SHA):
        raise ValueError('native TYPE bitmap differs from OS 1.11')
    sem, bp = planes(struct.unpack(f'>{COLUMNS}I', pixels))
    if hashlib.sha256(struct.pack(f'>{2*COLUMNS}I', *sem, *bp)).hexdigest() != PLANES_SHA:
        raise ValueError('unexpected SEM TYPE icon planes')
    start = ctx.append_asm('sem_type', source(sem, bp))
    symbols = {m[2]: int(m[1], 16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$', subprocess.check_output(
            [str(native.T.BIN/'binutils/nm-new'), '-n', str(ctx.work/'sem_type.elf')], text=True))}
    if symbols['sem_page_draw'] != start:
        raise ValueError('sem_page_draw is not the helper start')
    ctx.replace(PAGE_DRAW, PAGE_PROLOGUE, b'\x4e\xf9' + struct.pack('>I', symbols['sem_page_draw']) + b'\x4e\x71')
    ctx.replace(INIT_IMMEDIATE, struct.pack('>I', NATIVE_DRAWER), struct.pack('>I', symbols['sem_type_draw']))
    keep = ('sem_page_draw', 'sem_page_body', 'sem_type_draw', 'sem_type_bitmap', 'sem_type_bp_bitmap',
            'sem_type_flag')
    return dict(entry=hex(start), methods={k: hex(symbols[k]) for k in keep},
                patches={hex(PAGE_DRAW): 'jmp sem_page_draw; nop', hex(INIT_IMMEDIATE): 'record 38 drawer'},
                native_bitmap=dict(pixels=hex(PIXELS), pixels_sha256=PIXELS_SHA, mask=hex(MASK), mask_sha256=MASK_SHA),
                planes_sha256=hashlib.sha256(struct.pack(f'>{2*COLUMNS}I', *sem, *bp)).hexdigest(),
                limits=['The flag is set only while the FILTER page draw runs; ID 38 drawn elsewhere stays native.',
                        'TYPE 127 shows the BP icon alone, without slider or marker.'])
