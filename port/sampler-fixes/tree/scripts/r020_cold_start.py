"""Defer SLICE companion I/O until the private filesystem has initialized."""
from build_dn2_sampler_fixes_r014 import BE, need


def apply(ctx):
    cfg = ctx.doc['emulator_fixes_r019']['r019_project']
    startup = int(ctx.doc['sample_fs_startup']['methods']['sample_fs_status'], 16)
    mounted = int(cfg['constants']['FS_READY'], 16)
    need(startup == 0x47a9cd7c and mounted == 0x46b9608c,
         'unexpected filesystem readiness addresses')
    site, resume, deferred = 0x47ace7a4, 0x47ace7b0, 0x47acea6e
    # FS_READY belongs to private BSS, cleared by the first UI startup poll.
    # It can contain stale DDR before that poll; runtime startup status is
    # initialized by the bootstrap and is the authoritative first guard.
    entry = ctx.append_asm('slice_cold_start_gate', f'''.text
 move.w %sr,%d0
 andi.l #0x700,%d0
 bne.s defer
 move.l {startup:#x},%d0
 cmpi.l #2,%d0
 bne.s defer
 move.l {mounted:#x},%d0
 cmpi.l #1,%d0
 bne.s defer
 jmp {resume:#x}
defer:
 jmp {deferred:#x}
''')
    ctx.replace(site, bytes.fromhex('40c0028000000700660002c0'),
                b'\x4e\xf9' + BE(entry) + b'\x4e\x71' * 3)
    return dict(entry=hex(entry), site=hex(site), resume=hex(resume),
                deferred=hex(deferred), startup_status=hex(startup), mounted=hex(mounted),
                required_startup_status=2, required_mounted=1, deferred_status=4,
                guards_before_allocation=True, interrupt_mask_guard_preserved=True,
                limits=['Physical cold boot remains to verify.'])
