"""Carry incremental ProjectSettings edits into the working sample snapshot."""
import re
import subprocess

from build_dn2_sampler_fixes_r014 import BE
import build_dn2_source_page_route as route


def apply(ctx):
    doc = ctx.doc
    active = doc['project_sample_active']
    recorder = doc['recorder_persistence']
    constants = dict(
        PROJECT_LOCK=int(doc['sample_restore_lifecycle']['methods']['sample_restore_lock'], 16),
        ACTIVE_STATE_PTR=int(active['state_pointer'], 16),
        PROJECT_PUBLISH=int(active['methods']['sample_project_publish'], 16),
        RECORDER_PACK=int(recorder['methods']['recorder_persist_pack'], 16),
        RECORDER_STATE=int(doc['recording_settings']['settings_address'], 16),
        CURRENT_PROJECT=0x446478d0, MIRROR=0x405cd96c,
        SETTINGS_OFFSET=0x12190f1, STORED_SETTINGS_OFFSET=0xc3e000,
        NATIVE_SERIALIZE=0x400df57a)
    source = '\n'.join(f'.equ {k},{v:#x}' for k, v in constants.items())+'\n'
    source += '''.text
.global sample_working_settings_serialize
sample_working_settings_serialize:
 /* This call runs in the existing settings worker, after its queue mutex
  * has been released. Pool mutations and full snapshots use the same lock. */
 lea -20(%sp),%sp
 movem.l %d2/%a2-%a5,(%sp)
 movea.l 24(%sp),%a2
 movea.l 28(%sp),%a3
 pea PROJECT_LOCK
 jsr 0x40001608
 addq.l #4,%sp
 move.l 32(%sp),-(%sp)
 move.l %a3,-(%sp)
 move.l %a2,-(%sp)
 jsr NATIVE_SERIALIZE
 lea 12(%sp),%sp
 move.l %d0,%d2
 tst.b %d2
 beq.w settings_done
 cmpa.l #MIRROR+STORED_SETTINGS_OFFSET,%a2
 bne.w settings_done
 movea.l CURRENT_PROJECT,%a0
 tst.l %a0
 beq.w settings_done
 movea.l 16(%a0),%a0
 tst.l %a0
 beq.w settings_done
 movea.l %a0,%a1
 adda.l #SETTINGS_OFFSET,%a1
 cmpa.l %a1,%a3
 bne.w settings_done
 move.l 8(%a0),%d0
 cmp.l MIRROR+24,%d0
 bne.w settings_done
 movea.l ACTIVE_STATE_PTR,%a4
 tst.l %a4
 beq.w settings_done
 moveq #1,%d0
 cmp.l 4(%a4),%d0
 bne.w settings_done
 cmpa.l 12(%a4),%a0
 bne.w settings_done
 move.l MIRROR+24,%d0
 cmp.l 8(%a4),%d0
 bne.w settings_done
 lea 0x4210(%a4),%a5
 moveq #1,%d0
 cmp.l 4(%a5),%d0
 bne.w settings_publish
 move.l #128,%d0
 cmp.l (%a5),%d0
 bne.w settings_publish
 move.l #MIRROR,%d0
 cmp.l 12(%a5),%d0
 bne.w settings_publish
 move.l MIRROR+24,%d0
 cmp.l 8(%a5),%d0
 bne.w settings_publish
 /* Most settings notifications do not edit samples. Avoid recomputing
  * a 16 KiB CRC on tempo/mute/Recorder changes. No allocation or I/O. */
 lea 528(%a4),%a0
 lea 528(%a5),%a1
 move.l #4096,%d1
settings_compare:
 move.l (%a0)+,%d0
 cmp.l (%a1)+,%d0
 bne.w settings_publish
 subq.l #1,%d1
 bne.s settings_compare
 /* Recorder preferences share the header and issue the same native
  * settings notification. Refresh only their existing 24-byte record. */
 lea -24(%sp),%sp
 movea.l %sp,%a2
 pea RECORDER_STATE
 move.l %a2,-(%sp)
 jsr RECORDER_PACK
 addq.l #8,%sp
 movea.l %a2,%a0
 lea 48(%a5),%a1
 moveq #6,%d1
settings_prefs_compare:
 move.l (%a0)+,%d0
 cmp.l (%a1)+,%d0
 bne.s settings_prefs_write
 subq.l #1,%d1
 bne.s settings_prefs_compare
 lea 24(%sp),%sp
 bra.s settings_done
settings_prefs_write:
 clr.l 4(%a5)
 movea.l %a2,%a0
 lea 48(%a5),%a1
 moveq #6,%d1
settings_prefs_copy:
 move.l (%a0)+,%d0
 move.l %d0,(%a1)+
 subq.l #1,%d1
 bne.s settings_prefs_copy
 lea 24(%sp),%sp
 moveq #1,%d0
 move.l %d0,4(%a5)
 bra.s settings_done
settings_publish:
 pea 128
 move.l MIRROR+24,-(%sp)
 pea MIRROR
 move.l %a4,-(%sp)
 move.l %a5,-(%sp)
 jsr PROJECT_PUBLISH
 lea 20(%sp),%sp
settings_done:
 pea PROJECT_LOCK
 jsr 0x4000172a
 addq.l #4,%sp
 move.l %d2,%d0
 movem.l (%sp),%d2/%a2-%a5
 lea 20(%sp),%sp
 rts
'''
    entry = ctx.append_asm('sample_working_mirror', source)
    symbols = {m[2]: int(m[1], 16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$', subprocess.check_output(
            [str(route.B.T.BIN/'binutils/nm-new'), '-n',
             str(ctx.work/'sample_working_mirror.elf')], text=True))}
    assert symbols['sample_working_settings_serialize'] == entry
    ctx.replace(0x400469fe, b'\x4e\xb9'+BE(constants['NATIVE_SERIALIZE']),
                b'\x4e\xb9'+BE(entry))
    return dict(entry=hex(entry), site='0x400469fe',
                methods={'sample_working_settings_serialize': hex(entry)},
                constants={k: hex(v) for k, v in constants.items()},
                behavior='Native incremental settings serialization also publishes '
                         'the current sample identities and Recorder preferences '
                         'into the existing working-project backup companion.',
                guards=['Successful native settings serialization',
                        'Fixed working mirror destination and current raw settings owner',
                        'Current raw and serialized project UIDs match',
                        'Ready active companion owned by current raw Project with matching UID'],
                unchanged=['Explicit saved-project slots', 'Native backup scheduling',
                           'Power-off interrupt path', 'DSP and USB code',
                           'Audio buffer ownership and control-frame order'],
                limits=['A frozen task or abrupt power loss can still prevent queued '
                        'native autosave work from completing.'])
