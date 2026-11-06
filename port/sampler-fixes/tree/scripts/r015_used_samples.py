"""Classify stored SAMP locks by the step's effective Sound Machine."""
from struct import pack

LOCK_READER = 0x47A74F08
CACHE_TRACK_LOAD = 0x47A62950
CACHE_LOCK_CALL = 0x47A62F22

# Bitmap and restore order pass a PatternLocks owner. Incremental scan passes
# a PatternTrack. Both native readers return the stored sample index or -1.
SOURCE = '''.text
 bra.w from_owner
 bra.w from_track
from_owner:
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 jsr 0x4003cdba
 lea 16(%sp),%sp
 cmpi.l #1023,%d0
 bhi.s early_absent
 lea -20(%sp),%sp
 movem.l %d2-%d4/%a2-%a3,(%sp)
 move.l %d0,%d2
 movea.l 24(%sp),%a2
 lea -0x8b0(%a2),%a2
 move.l 28(%sp),%d3
 move.l 32(%sp),%d4
 move.l %d3,-(%sp)
 move.l %a2,-(%sp)
 jsr 0x4003b2ea
 addq.l #8,%sp
 movea.l %d0,%a0
 bra.s resolve

early_absent:
 moveq #-1,%d0
 rts
from_track:
 move.l 12(%sp),-(%sp)
 move.l 12(%sp),-(%sp)
 move.l 12(%sp),-(%sp)
 jsr 0x4004eaa4
 lea 12(%sp),%sp
 cmpi.l #1023,%d0
 bhi.s early_absent
 lea -20(%sp),%sp
 movem.l %d2-%d4/%a2-%a3,(%sp)
 move.l %d0,%d2
 movea.l 24(%sp),%a0
 move.l 60(%a0),%d3
 move.l 28(%sp),%d4
 /* Invert native 4003b2ea: track = pattern + 0x70 + 132 * index. */
 move.l #132,%d0
 mulu.l %d3,%d0
 lea -0x70(%a0),%a2
 suba.l %d0,%a2
resolve:
 /* d2 = validated SAMP lock, d3 = track, d4 = step, a2 = Pattern. */
 move.l %a0,-(%sp)
 jsr 0x4018a97a
 movea.l (%sp)+,%a0
 tst.l %d0
 beq.w absent
 movea.l %d0,%a3
 move.l (%a0),%d1
 beq.w base_sound
 movea.l %d1,%a1
 tst.l 40(%a1)
 beq.w base_sound
 move.l %d4,-(%sp)
 move.l %a0,-(%sp)
 jsr 0x4004eb1c
 addq.l #8,%sp
 mvz.b %d0,%d4
 cmpi.l #127,%d4
 bhi.w base_sound
 /* The Project's native pool validity check precedes preset lookup. */
 movea.l %a3,%a0
 adda.l #0x4f358,%a0
 move.l (%a0),%d1
 beq.w base_sound
 movea.l %d1,%a1
 move.l 104(%a1),%d1
 beq.w base_sound
 movea.l %d1,%a1
 move.l %d4,-(%sp)
 move.l %a0,-(%sp)
 jsr (%a1)
 addq.l #8,%sp
 tst.b %d0
 beq.s base_sound
 move.l %d4,-(%sp)
 move.l %a3,-(%sp)
 jsr 0x4003e426
 addq.l #8,%sp
 /* Native 4003e426/4004dfb0 returns an embedded object, even for slot 0. */
 movea.l %d0,%a0
 move.l (%a0),%d1
 beq.s base_sound
 movea.l %d1,%a1
 tst.l 40(%a1)
 beq.s base_sound
 move.l %a0,-(%sp)
 jsr 0x4004b7f2
 addq.l #4,%sp
 tst.l %d0
 bpl.s classify
base_sound:
 move.l %a3,-(%sp)
 jsr 0x4003efa8
 addq.l #4,%sp
 cmp.l %a2,%d0
 bne.s saved_sound
 lea 244(%a3),%a0
 move.l %d3,-(%sp)
 move.l %a0,-(%sp)
 jsr 0x40030e66
 addq.l #8,%sp
 move.l %d0,-(%sp)
 jsr 0x4004b7f2
 addq.l #4,%sp
 bra.s classify
saved_sound:
 move.l %a2,%d0
 sub.l %a3,%d0
 subi.l #0x4414,%d0
 move.l #0x954,%d1
 divu.l %d1,%d0
 cmpi.l #127,%d0
 bhi.s absent
 lea 244(%a3),%a0
 move.l %d0,-(%sp)
 move.l %a0,-(%sp)
 jsr 0x4019172e
 addq.l #8,%sp
 tst.l %d0
 beq.s absent
 movea.l %d0,%a0
 move.l #1163,%d0
 mulu.l %d3,%d0
 lea 52(%a0,%d0.l),%a0
 mvz.b 222(%a0),%d0
classify:
 subq.l #5,%d0
 cmpi.l #5,%d0
 bhi.s absent
 move.l %d2,%d0
 bra.s done
absent:
 moveq #-1,%d0
done:
 movem.l (%sp),%d2-%d4/%a2-%a3
 lea 20(%sp),%sp
 rts
'''


def apply(ctx):
    assert int(ctx.doc['used_samples']['methods']['used_sample_lock'], 16) == LOCK_READER
    assert int(ctx.doc['pool_lock_references']['symbols']['pool_pattern_track'], 16) == 0x47A62E64
    entry = ctx.append_asm('r015-used-sample-sound-lock', SOURCE)
    ctx.replace(LOCK_READER, bytes.fromhex('4feffff048d7041c'),
                b'\x4e\xf9' + pack('>I', entry) + b'\x4e\x71')
    ctx.replace(CACHE_TRACK_LOAD, bytes.fromhex('45f947a62e64'), bytes.fromhex('45f94003b2ea'))
    ctx.replace(CACHE_LOCK_CALL, bytes.fromhex('4eb94004eaa4'), b'\x4e\xb9' + pack('>I', entry + 4))
    return dict(owner_entry=hex(entry), track_entry=hex(entry + 4), existing_owner_entry=hex(LOCK_READER),
                cache_track_load=hex(CACHE_TRACK_LOAD), cache_lock_call=hex(CACHE_LOCK_CALL),
                consumers=['SELECT UNUSED bitmap', 'project restore ordering', 'incremental pattern reference cache'],
                behavior='Classify a bounded SAMP lock using its step Sound Machine. Use the live or saved base track when the preset is unavailable.')
