"""Select a populated project slot when a sampler SYN page is randomized."""
from build_dn2_sampler_fixes_r014 import BE, need


def apply(ctx):
    # DT2 1.16 invoker 0x400c8b5e draws from the project's valid identity
    # records. Its enumeration at 0x4004e4f6 excludes OFF and uses the
    # three-field empty predicate at 0x400e6172. Scan in place to avoid a
    # temporary vector allocation. Cap the donor's inclusive RNG endpoint.
    ids = [ctx.doc['slot_maps'][str(k)][3] for k in range(5, 11)]
    need(sorted(ids) == [4, 325, 334, 344, 352, 361], 'unexpected SAMP parameters')
    resolver = ctx.doc['browser_parameters']['symbols']['browser_sample_id']
    identity = ctx.doc['browser_identity_lookup']
    need(identity['slots'] == 1024 and identity['identity_stride'] == 16,
         'unexpected project identity layout')
    compare = '\n'.join(f' cmpi.l #{i},%d2\n beq.s candidate' for i in ids)
    entry = ctx.append_asm('sample_page_randomizer', f'''.text
{compare}
original:
 jsr 0x400c2418
 jmp 0x40039772
candidate:
 /* D4 is the Parameter receiver, D2 the requested native ID. Verify that
    the Sound owned by this receiver really assigns that ID to SAMP. */
 movea.l %d4,%a0
 tst.l %a0
 beq.s original
 tst.l 16(%a0)
 beq.s original
 pea 205.w
 move.l %d4,-(%sp)
 jsr {resolver}
 addq.l #8,%sp
 cmp.l %d2,%d0
 bne.s original
 /* Retire the lookup argument, then reuse the native setter and cleanup.
    This path did not acquire a callback, so its destructor stays empty. */
 addq.l #4,%sp
 clr.l -8(%a6)
 bsr.w choose_slot
 move.l %d0,%d3
 beq.s no_sample
 jmp 0x400398b4
no_sample:
 jmp 0x400398d4
choose_slot:
 lea -16(%sp),%sp
 movem.l %d2-%d4/%a2,(%sp)
 jsr {identity['current_project_getter']}
 tst.l %d0
 beq.s no_slot
 addi.l #0x30,%d0
 move.l %d0,-(%sp)
 jsr {identity['active_settings_resolver']}
 addq.l #4,%sp
 tst.l %d0
 beq.s no_slot
 movea.l %d0,%a2
 /* Settings resolver returns active record + 0x3e. Slot 0 is at record
    + 0x210. Start at slot 1, sixteen bytes after slot 0. */
 lea 0x1e2(%a2),%a2
 moveq #-1,%d4
scan:
 movea.l %a2,%a0
 moveq #1,%d2
 moveq #0,%d3
next_slot:
 moveq #-1,%d0
 cmp.l (%a0),%d0
 beq.s advance
 tst.l 4(%a0)
 beq.s advance
 tst.l 8(%a0)
 beq.s advance
 cmp.l %d3,%d4
 beq.s found
 addq.l #1,%d3
advance:
 lea 16(%a0),%a0
 addq.l #1,%d2
 cmpi.l #1024,%d2
 bcs.s next_slot
 tst.l %d4
 bpl.s no_slot
 tst.l %d3
 beq.s no_slot
 jsr 0x40150670
 andi.l #0x7fff,%d0
 lsr.l #8,%d0
 mulu.l %d3,%d0
 moveq #127,%d1
 divu.l %d1,%d0
 move.l %d0,%d4
 cmp.l %d3,%d4
 bcs.s scan
 subq.l #1,%d4
 bra.s scan
no_slot:
 moveq #0,%d0
 bra.s done
found:
 move.l %d2,%d0
done:
 movem.l (%sp),%d2-%d4/%a2
 lea 16(%sp),%sp
 rts
''')
    site = 0x4003976c
    ctx.replace(site, b'\x4e\xb9' + BE(0x400c2418), b'\x4e\xf9' + BE(entry))
    return dict(entry=hex(entry), lookup_site=hex(site), sample_ids=ids)
