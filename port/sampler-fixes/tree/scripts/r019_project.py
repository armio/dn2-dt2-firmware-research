"""Restore SLICE-grid persistence through the unchanged native Sound codec."""
from pathlib import Path
import re
import struct
import subprocess

from build_dt2_sampler_runtime import T


def apply(ctx):
    doc = ctx.doc
    assert 'slice_persistence' not in doc
    assert doc['slot_maps']['10'][15:25] == [0]*10
    poll = int(doc['sample_fs_startup']['entry'], 16)
    copy = next(r for r in doc['copies'] if int(r['destination'],16)<=poll<int(r['destination'],16)+r['bytes'])
    poll_flash = int(copy['source'],16)+poll-int(copy['destination'],16)
    offset = poll_flash-0x40000400
    before_poll = bytes(ctx.image[offset:offset+6])
    assert before_poll[:2] == b'\x4e\xf9'
    clear = int(doc['slice_storage']['methods']['clear'], 16)
    info = next(s for s in doc['slice_storage']['spans'] if s['name']=='slice_info_vtable')
    # Verified donor bindings in pinned R018 fn_new_map.txt / ram_map.txt.
    constants = dict(FS_OPEN=0x47a3648e, FS_READ=0x47a36246,
        FS_WRITE=0x47a362a6, FS_CLOSE=0x47a3644c, FS_RESOLVE=0x468026d4, FS_REMOVE=0x47a9e228,
        FS_READY=0x46b9608c, POLL_DELEGATE=int.from_bytes(before_poll[2:], 'big'),
        CLEAR_RETURN=clear+0x80, SLICE_INFO=int(info['runtime'],16)+8)
    source = '\n'.join(f'.equ {k},{v:#x}' for k,v in constants.items())+'\n'
    source += (Path(__file__).parent/'asm/dn2_slice_persistence.S').read_text()
    # A failed newly-created immutable object must not poison its content key
    # forever. Never remove a file that existed before this write attempt.
    old = 'io_fail:\n addq.l #1,slice_storage_failures'
    assert source.count(old)==1
    source = source.replace(old, '''io_fail:
 tst.l %d5
 beq.s cleanup_done
 cmpi.l #2,%d2
 bne.s cleanup_done
 pea 808(%a3)
 jsr FS_REMOVE
 addq.l #4,%sp
cleanup_done:
 addq.l #1,slice_storage_failures''')
    old=' jsr FS_OPEN\n lea 12(%sp),%sp\n tst.l %d0\n bne.w io_error\n'
    assert source.count(old)==1
    source=source.replace(old,old+' moveq #2,%d2\n')
    source=source.replace(' bra.s io_free',' bra.w io_free')
    old=' bne.s poll_track\npoll_done:'
    assert source.count(old)==1
    source=source.replace(old,''' bne.s poll_track
 /* Sound-lock pool records also deserialize before mounting at boot.
  * Resolve at most one per ordinary UI poll, never from the audio frame. */
 movea.l 0x446478d0,%a0
 movea.l 16(%a0),%a3
 tst.l %a3
 beq.w poll_done
 adda.l #0x11f425b,%a3
 move.l #128,%d2
poll_pool:
 mvz.b 222(%a3),%d0
 cmpi.l #10,%d0
 bne.s pool_next
 move.l 100(%a3),%d0
 cmpi.l #0x534c4631,%d0
 bne.s pool_next
 tst.l 375(%a3)
 bne.s pool_next
 tst.l 1147(%a3)
 bne.s pool_next
 move.l %a3,-(%sp)
 bsr.w slice_storage_restore
 addq.l #4,%sp
 bra.s poll_done
pool_next:
 adda.l #1163,%a3
 subq.l #1,%d2
 bne.s poll_pool
poll_done:''')
    source=source.replace(' beq.s poll_done',' beq.w poll_done')
    # Count every failed Sound serialization, including deferred filesystem
    # work. Native aggregate serializers ignore the individual return values.
    old = ' and.l %d2,%d0\n movem.l (%sp),%d2/%a2-%a3'
    assert source.count(old)==1
    source = source.replace(old, ''' and.l %d2,%d0
 tst.l %d0
 bne.s save_result_done
 addq.l #1,slice_storage_save_failures
save_result_done:
 movem.l (%sp),%d2/%a2-%a3''')
    source += '\n.global slice_storage_save_failures\nslice_storage_save_failures: .long 0\n'
    source = re.sub(r'(?m)^ cmpi\.([bl]) (#[^,]+),([^\n]*\(%a[023]\))$',
        lambda m:f' {"mvz.b" if m[1]=="b" else "move.l"} {m[3]},%d0\n cmpi.l {m[2]},%d0',source)
    source = re.sub(r'(?m)^ move\.l (#0x534c4631),([^\n]*\(%a2\))$',
                    r' move.l \1,%d0\n move.l %d0,\2',source)
    entry = ctx.append_asm('slice_persistence', source)
    symbols = {m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
        subprocess.check_output([str(T.BIN/'binutils/nm-new'),'-n',
                                 str(ctx.work/'slice_persistence.elf')],text=True))}
    def redirect(address, before, name):
        ctx.replace(address, before, b'\x4e\xf9'+struct.pack('>I',symbols[name])
                    +b'\x4e\x71'*((len(before)-6)//2))
    redirect(0x400dd6a6, bytes.fromhex('4fefffdc48d77c3c'), 'slice_storage_save')
    redirect(0x400dd1ea, bytes.fromhex('4fefffe048d77c1c'), 'slice_storage_load')
    redirect(clear+0x78, bytes.fromhex('42a801774cd7040c'), 'slice_storage_clear')
    redirect(poll_flash, before_poll, 'slice_storage_poll')
    project = 0x400e1494
    original = bytes(ctx.image[project-0x40000400:project-0x40000400+6])
    assert original[:2] == b'\x4e\xf9'
    delegate = int.from_bytes(original[2:], 'big')
    project_save = ctx.append_asm('slice_project_save_result', f'''.text
 move.l %d2,-(%sp)
 move.l {symbols['slice_storage_save_failures']:#x},%d2
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 move.l 24(%sp),-(%sp)
 jsr {delegate:#x}
 lea 20(%sp),%sp
 cmp.l {symbols['slice_storage_save_failures']:#x},%d2
 beq.s done
 moveq #0,%d0
done:
 move.l (%sp)+,%d2
 rts
''')
    ctx.replace(project, original, b'\x4e\xf9'+struct.pack('>I',project_save))
    # A rejected native project leaves the current raw project intact. Keep
    # its active sample-identity entry valid until a replacement has decoded.
    ctx.replace(0x47a758b8,bytes.fromhex('42ac00044a02671e'),
                bytes.fromhex('4a02672242ac0004'))
    ctx.replace(0x47a75f46,bytes.fromhex('42aa00044a02672c'),
                bytes.fromhex('4a02673042aa0004'))
    return dict(entry=hex(entry), methods={k:hex(v) for k,v in symbols.items()
                if k.startswith('slice_storage_')},
        project_save=hex(project_save),project_save_delegate=hex(delegate),
        rejected_project_preserves_active_sample_validity=True,
        constants={k:hex(v) for k,v in constants.items()},
        descriptor=dict(magic='SLF1', raw_offset=100, stored_offset=124, bytes=20),
        map=dict(raw_offset=375, bytes=772, count_max=64),
        file=dict(path='/.slc_<128-bit content key>', bytes=776),
        limits=['Sound exports need their immutable slice companion files.',
                'Previously discarded grids cannot be recovered from native359-byte Sounds.',
                'Physical save/reload remains to verify.'])
