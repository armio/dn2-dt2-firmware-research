"""Finish private sampler control initialization and route SYN page operations."""
from build_dn2_sampler_fixes_r014 import BE, need


def apply(ctx):
    cfg = ctx.doc['encoder_sensitivity']
    rows = sorted(cfg['rows'], key=lambda row: int(row['companion'], 16))
    base = int(cfg['row_base'], 16)
    need(len(rows) == 35 and all(int(row['companion'], 16) == base + i*100
                                 for i, row in enumerate(rows)), 'unexpected private companions')
    # The original initializer leaves A2 = private row, D2 = row index * 16.
    # TUNE already borrows the native octave callback. The DT2 excludes both
    # TUNE and LEV from randomization. All other controls get both callbacks.
    policies = [0 if row['name'] == 'TUNE' else 1 if row['name'] == 'LEV' else 2
                for row in rows]
    need([policies.count(i) for i in range(3)] == [5, 6, 24], 'unexpected control types')
    helper = ctx.append_asm('sampler_init_gestures', f'''.text
 lsr.l #4,%d2
 lea policies(%pc),%a0
 mvz.b (%a0,%d2.l),%d1
 tst.l %d1
 beq.s initialized
 lea 0x42431ed8,%a0
 move.l (%a0)+,52(%a2)
 move.l (%a0)+,56(%a2)
 move.l (%a0)+,60(%a2)
 move.l (%a0),64(%a2)
 cmpi.l #2,%d1
 bne.s initialized
 lea 0x42432128,%a0
 move.l (%a0)+,36(%a2)
 move.l (%a0)+,40(%a2)
 move.l (%a0)+,44(%a2)
 move.l (%a0),48(%a2)
initialized:
 moveq #1,%d0
 move.l %d0,96(%a2)
 rts
policies:
 .byte {','.join(map(str, policies))}
''')
    # Replace only the existing two instructions that mark the row initialized.
    site = int(cfg['entry'], 16) + 0x70
    ctx.replace(site, bytes.fromhex('700125400060'), b'\x4e\xb9' + BE(helper))

    vtable = int(ctx.doc['sampler_ui_actions']['clear_vtable_site'], 16) - 0xdc
    # DN2 MultiSource methods normalize -1 through the current page virtual
    # accessor before passing the operation to native Project storage.
    methods = ((0xd4, 0x47a9c2d8, 0x4001836c), (0xd8, 0x47a9c36c, 0x40018414),
               (0xe0, 0x47a9c584, 0x400160d6), (0xe4, 0x47a9c5e0, 0x40016048))
    for offset, original, native in methods:
        native_slot = 0x401d49a0 + offset - 0x40000400
        need(ctx.image[native_slot:native_slot+4] == BE(native), 'stock page action differs')
        ctx.replace(vtable + offset, BE(original), BE(native))

    # The bank refresh uses the DT2 SAMP alias. Resolve it for the actual
    # selected Sound before invoking the native trig-lock getter.
    getter = int(ctx.doc['browser_parameters']['symbols']['browser_sample_lock_get'], 16)
    ctx.replace(0x47a5fc36, bytes.fromhex('206800404e90'), b'\x4e\xb9' + BE(getter))
    return dict(private_initializer=hex(helper), func_default_rows=30, randomizer_rows=24,
                source_actions=[hex(vtable+offset) for offset, _, _ in methods],
                held_bank_getter=hex(getter))
