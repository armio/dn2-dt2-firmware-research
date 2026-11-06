"""Guard native song conversion and the two optional sequencer list/event pointers."""
import struct


def apply(ctx):
    def redirect(name, address, before, body):
        target = ctx.append_asm(name, '.text\n' + body)
        ctx.replace(address, bytes.fromhex(before), b'\x4e\xf9' + struct.pack('>I', target))
        return hex(target)

    # Null checks and the stored version check have already passed at both sites.
    # Return the native failure code before touching the destination on bad counts.
    load = redirect('song_load_rows', 0x400dea8c, '4878 0010 2f0a', '''
 mvz.w 2891(%a3),%d0
 cmpi.l #99,%d0
 bhi.s invalid
 pea 16.w
 move.l %a2,-(%sp)
 jmp 0x400dea92
invalid:
 jmp 0x400deb56
''')
    save = redirect('song_save_rows', 0x400deb7e, '4878 0010 240a', '''
 move.l 3679(%a3),%d0
 cmpi.l #99,%d0
 bhi.s invalid
 pea 16.w
 move.l %a2,%d2
 jmp 0x400deb84
invalid:
 jmp 0x400dec5e
''')
    # A Euclidean rest can be probed without a destination event.
    rest = redirect('euclidean_rest_event', 0x400d86fc, '42ab 0004 600c', '''
 tst.l %a3
 beq.s empty
 clr.l 4(%a3)
empty:
 jmp 0x400d870e
''')
    # Expiring the tail still serializes its Note Off and frees it. Only a
    # surviving successor has a previous-node link to clear.
    expiry = redirect('midi_note_successor', 0x4012b544, '2243 42ae 0010', '''
 move.l %d3,%a1
 tst.l %fp
 beq.s tail
 clr.l 16(%fp)
tail:
 jmp 0x4012b54a
''')
    return dict(song_load=load, song_save=save, euclidean_rest=rest, midi_note_expiry=expiry)
