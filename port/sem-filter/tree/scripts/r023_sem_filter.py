"""Expose one SEM filter ID while retaining native MULTI-MODE controls.

Raw Sound filter ID 6 is permanent; DSP dispatch is a separate component.
Only control access maps it to native type 0. Identity, serialization and
outgoing control frames retain 6. TYPE 0..126 morphs LP/notch/HP; 127 is BP.
"""
import re
import struct
import subprocess

import build_dt2_sampler_runtime as native

FILTER_ID = 6
RAW_CALLERS = (0x40045940, 0x40045a5e, 0x40045b34, 0x4004607a,
               0x40071ece, 0x400d5a84, 0x400d6798, 0x400d71c0,
               0x4006ec9a, 0x4006efce, 0x4006f006)


def apply(ctx):
    old_slot = bytes(ctx.image[0x400dc032-native.BASE:0x400dc038-native.BASE])
    assert old_slot[:2] == b'\x4e\xf9'
    delegate = int.from_bytes(old_slot[2:], 'big')
    raw_checks = '\n'.join(f' cmpi.l #{p:#x},%d1\n beq.w sem_reader_raw' for p in RAW_CALLERS)
    # Like the native filter display, this is a topology schematic: cutoff
    # moves the knee/notch; resonance narrows it (and raises LP/HP/BP peaks).
    # No audio-rate math or new graphics allocator is introduced.
    levels = []
    for mode in range(128):
        left = 18 - max(0, mode-63)*10//63
        right = 18 - max(0, 63-mode)*10//63
        shift = int((63-mode)/8) if 0 < mode < 126 else 0
        if mode == 127: left = right = 8
        levels.extend((max(8,left), max(8,right), shift & 255, 0))
    graph_levels = ','.join(map(str, levels))
    source = f'''.text
.global sem_descriptor,sem_name,sem_label,sem_reader,sem_real_reader
.global sem_slot,sem_midi_filter,sem_list,sem_title,sem_desc_data
.global sem_graph_dispatch,sem_graph
sem_descriptor:
 move.l 4(%sp),%d0
 cmpi.l #6,%d0
 bne.s sem_descriptor_stock
 /* Native descriptor strings already exist before a page can request one.
  * Build the private descriptor once, preserving the original parameters. */
 tst.l sem_desc_ready
 bne.s sem_descriptor_ready
 lea 0x424329cc,%a0
 lea sem_desc_data,%a1
 moveq #10,%d0
sem_descriptor_copy:
 move.l (%a0)+,(%a1)+
 subq.l #1,%d0
 bpl.s sem_descriptor_copy
 move.l #sem_title,%d0
 move.l %d0,sem_desc_data
 move.l %d0,sem_desc_data+4
 moveq #1,%d0
 move.l %d0,sem_desc_ready
sem_descriptor_ready:
 move.l #sem_desc_data,%d0
 rts
sem_descriptor_stock:
 moveq #5,%d1
 move.l 4(%sp),%d0
 jmp 0x400c24b6
sem_name:
 move.l 4(%sp),%d0
 cmpi.l #6,%d0
 bne.s sem_name_stock
 move.l #sem_title,%d0
 rts
sem_name_stock:
 moveq #5,%d1
 move.l 4(%sp),%d0
 jmp 0x400dc3aa
sem_label:
 move.l 4(%sp),%d0
 cmpi.l #6,%d0
 bne.s sem_label_stock
 move.l #sem_title,%d0
 rts
sem_label_stock:
 moveq #5,%d1
 move.l 4(%sp),%d0
 jmp 0x400dc3d0
sem_reader:
 mvs.b 223(%a0),%d0
 cmpi.l #6,%d0
 bne.w sem_reader_done
 move.l %d1,-(%sp)
 move.l 8(%sp),%d1
 {raw_checks}
 cmpi.l #sem_real_return,%d1
 beq.w sem_reader_raw
 moveq #0,%d0
sem_reader_raw:
 move.l (%sp)+,%d1
sem_reader_done:
 jmp 0x4004b88c
sem_real_reader:
 move.l 4(%sp),-(%sp)
 jsr 0x4004b860
sem_real_return:
 addq.l #4,%sp
 rts
sem_midi_filter:
 mvs.b 223(%a0),%d0
 cmpi.l #6,%d0
 bne.s sem_midi_done
 moveq #0,%d0
sem_midi_done:
 rts
sem_slot:
 /* Mid-function: saved D2 at 0(sp), slot in A0, filter at 16(sp).
  * All non-filter slots retain the existing sampler resolver. */
 move.l 16(%sp),%d0
 cmpi.l #6,%d0
 bne.s sem_slot_stock
 move.l %a0,%d0
 subi.l #66,%d0
 cmpi.l #2,%d0
 bhi.s sem_slot_stock
 lea sem_slot_ids,%a1
 move.l (%a1,%d0.l*4),%d0
 move.l (%sp)+,%d2
 rts
sem_slot_stock:
 jmp {delegate:#x}
sem_graph_dispatch:
 cmpi.l #6,%d4
 beq.s sem_graph_selected
 /* Replaced native range check, with its original register/CCR effects. */
 moveq #5,%d0
 cmp.l %d4,%d0
 bcs.w sem_graph_stock_skip
 jmp 0x4006eca8
sem_graph_stock_skip:
 jmp 0x4006ed3a
sem_graph_selected:
 move.l %d2,-(%sp)
 move.l %d7,-(%sp)
 move.l %d6,-(%sp)
 move.l %d3,-(%sp)
 jsr sem_graph
 lea 16(%sp),%sp
 jmp 0x4006ed3a
sem_graph:
 /* bitmap, FREQ raw, RESO raw, TYPE coarse. Stack-local five-point graph. */
 lea -72(%sp),%sp
 movem.l %d2-%d7/%a2-%a3,(%sp)
 move.l 76(%sp),%d3
 move.l 80(%sp),%d4
 andi.l #32767,%d4
 moveq #48,%d0
 muls.l %d0,%d4
 moveq #15,%d0
 lsr.l %d0,%d4
 addi.l #22,%d4
 move.l 84(%sp),%d5
 andi.l #32767,%d5
 moveq #5,%d0
 muls.l %d0,%d5
 moveq #15,%d0
 lsr.l %d0,%d5
 moveq #8,%d0
 sub.l %d5,%d0
 move.l %d0,%d5
 move.l 88(%sp),%d2
 andi.l #127,%d2
 lea sem_graph_levels,%a0
 lea (%a0,%d2.l*4),%a0
 mvz.b (%a0),%d6
 mvz.b 1(%a0),%d7
 mvs.b 2(%a0),%d0
 add.l %d0,%d4
 /* Native box: x21..71, y7..23. Keep all interior points clipped. */
 cmpi.l #22,%d4
 bge.s sem_graph_xhi
 moveq #22,%d4
sem_graph_xhi:
 cmpi.l #70,%d4
 ble.s sem_graph_points
 moveq #70,%d4
sem_graph_points:
 lea 32(%sp),%a2
 move.l #22,(%a2)
 move.l %d6,4(%a2)
 move.l %d4,%d0
 sub.l %d5,%d0
 cmpi.l #22,%d0
 bge.s sem_graph_left
 moveq #22,%d0
sem_graph_left:
 move.l %d0,8(%a2)
 move.l %d6,12(%a2)
 move.l %d4,16(%a2)
 moveq #8,%d0
 tst.l %d2
 beq.s sem_graph_peak
 cmpi.l #126,%d2
 blo.s sem_graph_center
sem_graph_peak:
 move.l 84(%sp),%d0
 andi.l #32767,%d0
 lsr.l #8,%d0
 lsr.l #5,%d0
 addi.l #18,%d0
sem_graph_center:
 move.l %d0,20(%a2)
 move.l %d4,%d0
 add.l %d5,%d0
 cmpi.l #70,%d0
 ble.s sem_graph_right
 moveq #70,%d0
sem_graph_right:
 move.l %d0,24(%a2)
 move.l %d7,28(%a2)
 moveq #70,%d0
 move.l %d0,32(%a2)
 move.l %d7,36(%a2)
 clr.l -(%sp)
 pea 23
 pea 71
 pea 7
 pea 21
 move.l %d3,-(%sp)
 jsr 0x40114842
 lea 24(%sp),%sp
 moveq #3,%d4
sem_graph_line:
 pea 1
 move.l 12(%a2),-(%sp)
 move.l 8(%a2),-(%sp)
 move.l 4(%a2),-(%sp)
 move.l (%a2),-(%sp)
 move.l %d3,-(%sp)
 jsr 0x40114148
 lea 24(%sp),%sp
 addq.l #8,%a2
 subq.l #1,%d4
 bpl.s sem_graph_line
 pea 1
 pea 23
 pea 71
 pea 7
 pea 21
 move.l %d3,-(%sp)
 jsr 0x40114626
 lea 24(%sp),%sp
 /* Replace only this graph's TYPE caption with its actual response family. */
 lea sem_graph_lp_nt,%a3
 tst.l %d2
 bne.s sem_graph_caption_notch
 lea sem_graph_lp,%a3
 bra.s sem_graph_caption
sem_graph_caption_notch:
 cmpi.l #63,%d2
 bne.s sem_graph_caption_hp
 lea sem_graph_notch,%a3
 bra.s sem_graph_caption
sem_graph_caption_hp:
 blo.s sem_graph_caption
 lea sem_graph_nt_hp,%a3
 cmpi.l #126,%d2
 blo.s sem_graph_caption
 lea sem_graph_hp,%a3
 beq.s sem_graph_caption
 lea sem_graph_bp,%a3
sem_graph_caption:
 clr.l -(%sp)
 pea 31
 pea 71
 pea 24
 pea 21
 move.l %d3,-(%sp)
 jsr 0x40114842
 lea 24(%sp),%sp
 move.l %a3,-(%sp)
 pea 2
 pea 25
 pea 46
 pea 0x44507ed8
 move.l %d3,-(%sp)
 jsr 0x4011545c
 lea 24(%sp),%sp
 movem.l (%sp),%d2-%d7/%a2-%a3
 lea 72(%sp),%sp
 rts
sem_graph_lp: .asciz "LP"
sem_graph_lp_nt: .asciz "LP/NT"
sem_graph_notch: .asciz "NOTCH"
sem_graph_nt_hp: .asciz "NT/HP"
sem_graph_hp: .asciz "HP"
sem_graph_bp: .asciz "BP"
.balign 4
sem_graph_levels: .byte {graph_levels}
.balign 4
sem_slot_ids: .long 38,36,37
sem_list: .long 0,1,4,3,5,2,6
sem_title_rep: .long 3,3,-1
sem_title: .asciz "SEM"
.balign 4
sem_desc_ready: .long 0
sem_desc_data: .space 44
'''
    entry = ctx.append_asm('sem_filter_controls', source)
    symbols = {m[2]: int(m[1], 16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$', subprocess.check_output(
            [str(native.T.BIN/'binutils/nm-new'), '-n',
             str(ctx.work/'sem_filter_controls.elf')], text=True))}
    be = lambda v: struct.pack('>I', v)
    for at, old, name in (
        (0x400c24b0, '7205202f0004', 'sem_descriptor'),
        (0x400dc3a4, '7205202f0004', 'sem_name'),
        (0x400dc3ca, '7205202f0004', 'sem_label'),
        (0x4004b884, '712800df6002', 'sem_reader'),
        (0x4003649c, '712800df4e75', 'sem_midi_filter'),
        (0x400313e6, '4ef94004b860', 'sem_real_reader'),
    ):
        ctx.replace(at, bytes.fromhex(old), b'\x4e\xf9'+be(symbols[name]))
    ctx.replace(0x4006eca0, bytes.fromhex('7005b08465000094'),
                b'\x4e\xf9'+be(symbols['sem_graph_dispatch'])+b'\x4e\x71')
    ctx.replace(0x400dc032, old_slot, b'\x4e\xf9'+be(symbols['sem_slot']))
    ctx.replace(0x4004db0c, bytes.fromhex('48780018'), bytes.fromhex('4878001c'))
    ctx.replace(0x4004db32, bytes.fromhex('41e80018'), bytes.fromhex('41e8001c'))
    ctx.replace(0x4004db2e, be(0x401ddd58), be(symbols['sem_list']+28))
    ctx.replace(0x4004db38, be(0x401ddd40), be(symbols['sem_list']))
    # This bound is loaded after the synth-byte check and applies only to
    # the following filter byte. Existing -1..5 values retain native behavior.
    ctx.replace(0x400dd2bc, bytes.fromhex('143c0007'), bytes.fromhex('143c0008'))
    return dict(entry=hex(entry), methods={k:hex(v) for k,v in symbols.items()},
                raw_filter_id=6, control_host=0, type_slot=66,
                cutoff_slot=67, resonance_slot=68,
                mode_encoding='TYPE 0..126: LP through notch to HP; TYPE127: BP',
                selector_order=[0,1,4,3,5,2,6],
                control_frame='Native raw filter word at frame offset0xb2 unchanged',
                limits=['TYPE remains numeric; the graph caption identifies LP, LP/NT, NOTCH, NT/HP, HP or BP.',
                        'SEM graph is an illustrative topology schematic, not a measured frequency response or live modulation display; stock curves are unchanged.',
                        'CF controls alone do not supply the new DSP kernel.'])
