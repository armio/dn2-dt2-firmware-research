"""Reconcile the visible SYN page after an audio Machine changes family."""
import re
import struct
import subprocess

import build_dn2_source_page_route as route


def apply(ctx):
    doc = ctx.doc
    poll = int(doc['sample_fs_startup']['entry'], 16)
    copy = next(r for r in doc['copies']
                if int(r['destination'], 16) <= poll < int(r['destination'], 16)+r['bytes'])
    poll_flash = int(copy['source'], 16)+poll-int(copy['destination'], 16)
    offset = poll_flash-0x40000400
    before = bytes(ctx.image[offset:offset+6])
    assert before[:2] == b'\x4e\xf9'
    methods = doc['source_page_route']['methods']
    constants = dict(POLL_DELEGATE=int.from_bytes(before[2:], 'big'),
                     MAIN_PAIR=0x44647980,
                     ROUTE_CACHE=int(methods['source_route_cache'], 16),
                     SOURCE_PAIR=int(methods['source_page_pair'], 16),
                     SELECT_SYN=0x4005e7e4)
    source = '\n'.join(f'.equ {k},{v:#x}' for k, v in constants.items())+'\n'
    source += '''.text
.global source_route_poll,source_route_reconcile
source_route_poll:
 jsr POLL_DELEGATE
source_route_reconcile:
 /* Preserve the delegate's result and every register this check touches.
  * Native function-call CCR flags are volatile. No callback runs in an ISR. */
 lea -32(%sp),%sp
 movem.l %d0-%d2/%a0-%a4,(%sp)
 movea.l MAIN_PAIR+4,%a0
 tst.l %a0
 beq.w route_done
 tst.l 4(%a0)
 ble.w route_done
 movea.l MAIN_PAIR,%a2
 tst.l %a2
 beq.w route_done
 tst.l ROUTE_CACHE+12
 bne.w route_done
 movea.l 0xc0(%a2),%a0
 tst.l %a0
 beq.w route_done
 tst.l 4(%a0)
 ble.w route_done
 movea.l 0xbc(%a2),%a3
 tst.l %a3
 beq.w route_done
 tst.b 0x30(%a3)
 bne.w route_done
 movea.l 0x10c(%a2),%a4
 tst.l %a4
 beq.w route_done
 cmpa.l %a4,%a3
 beq.s route_syn
 cmpa.l ROUTE_CACHE,%a2
 bne.w route_done
 cmpa.l ROUTE_CACHE+4,%a3
 bne.w route_done
route_syn:
 /* Only an exposed SYN page can change. Even a closed modal must be
  * removed by the normal controller lifecycle before reconciliation. */
 movea.l 0x2c(%a2),%a0
 tst.l %a0
 beq.w route_done
 lea 0x14(%a0),%a1
 movea.l 4(%a1),%a0
 tst.l %a0
 beq.w route_done
 cmpa.l %a1,%a0
 beq.w route_done
 cmpa.l (%a0),%a1
 bne.w route_done
 cmpa.l 8(%a0),%a3
 bne.w route_done
 /* Selected-trigger editing can temporarily resolve another Sound's
  * Machine. Keep its page and lock-edit state until selection is released. */
 movea.l 0x6c(%a4),%a0
 tst.l %a0
 beq.w route_done
 tst.b 0x268(%a0)
 beq.s route_resolve
 move.l 0x258(%a0),%d0
 or.l 0x25c(%a0),%d0
 or.l 0x260(%a0),%d0
 or.l 0x264(%a0),%d0
 bne.w route_done
route_resolve:
 pea 0x10c(%a2)
 move.l %a2,-(%sp)
 jsr SOURCE_PAIR
 addq.l #8,%sp
 tst.l %d0
 beq.s route_done
 movea.l %d0,%a0
 cmpa.l (%a0),%a3
 beq.s route_done
 /* Reuse native shared ownership, close/open and redraw behavior. This
  * runs on the next UI poll, outside Machine-picker commit callbacks. */
 pea 1
 pea 1
 move.l %a2,-(%sp)
 jsr SELECT_SYN
 lea 12(%sp),%sp
route_done:
 movem.l (%sp),%d0-%d2/%a0-%a4
 lea 32(%sp),%sp
 rts
'''
    entry = ctx.append_asm('source_route_reconcile', source)
    symbols = {m[2]: int(m[1], 16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$', subprocess.check_output(
            [str(route.B.T.BIN/'binutils/nm-new'), '-n',
             str(ctx.work/'source_route_reconcile.elf')], text=True))}
    assert symbols['source_route_poll'] == entry
    ctx.replace(poll_flash, before, b'\x4e\xf9'+struct.pack('>I', entry))
    return dict(entry=hex(entry), methods={k: hex(v) for k, v in symbols.items()
                if k.startswith('source_route_')},
                constants={k: hex(v) for k, v in constants.items()},
                poll_entry=hex(poll), poll_flash=hex(poll_flash),
                behavior='After existing UI work, reconcile an exposed audio SYN page '
                         'through the existing Source factory and native selector.',
                guards=['Live MainScreen and current-page owners', 'No Source construction in progress',
                        'Current page is stock audio SYN or this MainScreen cached Source',
                        'Current page is open and owns the controller tail',
                        'No selected-trigger Sound-lock editing'],
                unchanged=['DSP code', 'Audio buffer ownership', 'SPI control-frame order',
                           'Machine assignment and Sound initialization'],
                limits=['Native replay cannot prove physical UI timing.'])
