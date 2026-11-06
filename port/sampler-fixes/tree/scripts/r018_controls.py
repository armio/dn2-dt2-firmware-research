"""Expose sampler SYN controls through DN2's existing MIDI parameter routes."""
from build_dn2_sampler_fixes_r014 import BE


def apply(ctx):
    lookups = {}
    for label, site, first in (('cc', 0x400dc814, 40), ('nrpn', 0x400dc8f6, 201)):
        code = ctx.append_asm('sampler_midi_' + label, f'''.text
 move.l 4(%sp),%d0
 cmpi.l #15,%d0
 bhi.s original
 move.l 8(%sp),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.s original
 move.l 16(%sp),%d1
 subi.l #{first},%d1
 cmpi.l #7,%d1
 bhi.s original
 move.l %d2,-(%sp)
 move.l %d1,%d2
 move.l 12(%sp),-(%sp)
 jsr 0x400c248e
 addq.l #4,%sp
 move.l %d0,%a0
 move.l 8(%a0,%d2.l*4),%d0
 move.l (%sp)+,%d2
 cmpi.l #10,%d0
 bne.s done
 moveq #0,%d0
done:
 rts
original:
 lea -12(%sp),%sp
 movem.l %d2-%d4,(%sp)
 jmp {site+8:#x}
''')
        ctx.replace(site, bytes.fromhex('4feffff448d7001c'), b'\x4e\xf9'+BE(code)+b'\x4e\x71')
        lookups[label] = hex(code)

    # SAMP stores an absolute 10-bit project index rather than a Q8 value.
    # Each incoming route already validates MIDI width and resolves its Machine.
    predicate = ctx.append_asm('sampler_midi_sample_id', '''.text
 cmpi.l #4,%d1
 beq.s found
 cmpi.l #325,%d1
 beq.s found
 cmpi.l #334,%d1
 beq.s found
 cmpi.l #344,%d1
 beq.s found
 cmpi.l #352,%d1
 beq.s found
 cmpi.l #361,%d1
found:
 rts
''')
    cc_value = ctx.append_asm('sampler_midi_cc_sample', f'''.text
 move.l %d0,-(%sp)
 move.l %d2,%d1
 jsr {predicate:#x}
 bne.s ordinary
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 move.l (%a2),%a0
 move.l 40(%a0),%a0
 jsr (%a0)
 addq.l #8,%sp
 andi.l #896,%d0
 lsr.l #8,%d4
 andi.l #127,%d4
 or.l %d0,%d4
ordinary:
 move.l (%sp)+,%d0
 tst.b %d0
 beq.s saved_sound
 move.l (%a2),%a0
 jmp 0x40038b6a
saved_sound:
 jmp 0x40038b82
''')
    ctx.replace(0x40038b64, bytes.fromhex('4a00671a2052'), b'\x4e\xf9'+BE(cc_value))
    nrpn_value = ctx.append_asm('sampler_midi_nrpn_sample', f'''.text
 move.l %d3,%d1
 jsr {predicate:#x}
 bne.s ordinary
 cmpi.l #1023,%d4
 bhi.s invalid
 move.l (%a2),%a0
 move.l %a2,-(%sp)
 jmp 0x400374a6
ordinary:
 move.l (%a2),%a0
 move.l %a2,-(%sp)
 add.l %d4,%d4
 jmp 0x400374a6
invalid:
 jmp 0x400374ea
''')
    ctx.replace(0x400374a0, bytes.fromhex('20522f0ad884'), b'\x4e\xf9'+BE(nrpn_value))
    # Keep output metadata separate from the stock registry initializer, whose
    # five-machine arrays cannot contain the added Machine types.
    visible = ((1,2,0,4,5,11,12,13), (350,351,0,352,353,354,355,356),
               (359,360,0,361,362,363,364,365), (0,333,0,334,335,336,337,338),
               (323,324,0,325,326,327,328,329), (341,342,0,344,345,346,0,347))
    pairs = '\n'.join(f'.long {pid},{knob}' for row in visible
                      for knob,pid in enumerate(row) if pid)
    for label, site, first in (('cc',0x400dc2a2,40), ('nrpn',0x400dc2ea,201)):
        code = ctx.append_asm('sampler_midi_output_'+label, f'''.text
 move.l 4(%sp),%d0
 lea mapping,%a0
next:
 move.l (%a0)+,%d1
 bmi.s original
 cmp.l %d0,%d1
 beq.s found
 addq.l #4,%a0
 bra.s next
found:
 move.l (%a0),%d0
 addi.l #{first},%d0
 rts
original:
 cmpi.l #368,%d0
 jmp {site+10:#x}
.balign 4
mapping:
{pairs}
.long -1
''')
        ctx.replace(site, bytes.fromhex('202f00040c8000000170'),
                    b'\x4e\xf9'+BE(code)+b'\x4e\x71'*2)
        lookups['out_'+label] = hex(code)
    for label,site,convert in (('cc',0x40037ac6,'andi.l #127,%d0\n lsl.l #8,%d0'),
                               ('nrpn',0x40037a8c,'add.l %d0,%d0')):
        code = ctx.append_asm('sampler_midi_output_value_'+label, f'''.text
 move.l 40(%a0),%a0
 jsr (%a0)
 move.l %d2,%d1
 jsr {predicate:#x}
 bne.s ordinary
 {convert}
ordinary:
 jmp {site+6:#x}
''')
        ctx.replace(site, bytes.fromhex('206800284e90'), b'\x4e\xf9'+BE(code))
    return dict(lookup=lookups, cc=[40,47], nrpn=[201,208], sample_cc=43,
                sample_nrpn=204, cc_sample_bank='preserve', nrpn_sample_max=1023,
                sample_cc_helper=hex(cc_value), sample_nrpn_helper=hex(nrpn_value))
