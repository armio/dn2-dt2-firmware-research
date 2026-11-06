"""Reject incomplete kit dumps and acknowledge only successful native imports."""
import struct


def apply(ctx):
    def redirect(name, address, before, source):
        original = bytes.fromhex(before)
        target = ctx.append_asm(name, '.text\n' + source)
        ctx.replace(address, original, b'\x4e\xf9' + struct.pack('>I', target)
                    + b'\x4e\x71' * ((len(original)-6)//2))
        return hex(target)

    # All supported kit versions occupy 0x2a00 decoded bytes. Both native
    # command routes ask the same constructor for that size. Reject short or
    # trailing data before an importer or a registered receive listener sees it.
    packet = redirect('kit_dump_packet', 0x400e4426, '4878 002c 4eb9 40120264', '''
 mvz.b %d4,%d0
 cmpi.l #0x52,%d0
 beq.s kit
 cmpi.l #0x5a,%d0
 bne.s ordinary
kit:
 cmpi.l #0x3000,%d2
 bne.s reject
 move.l %d5,%a1
 mvz.b (%a1),%d0
 andi.l #0x78,%d0
 cmpi.l #0x78,%d0
 bne.s reject
 move.l 1(%a1),%d0
 cmpi.l #0x3e6f3a4e,%d0
 bne.s reject
ordinary:
 pea 0x2c.w
 jsr 0x40120264
 jmp 0x400e4430
reject:
 jmp 0x400e43c6
''')

    # The converter already validates and upgrades versions. Its boolean
    # return must gate the project-changed signal and KIT RECEIVED notification.
    indexed = redirect('kit_dump_indexed_result', 0x4012418a,
                       '4e95 2f0b 4878 0001', '''
 tst.b %d0
 beq.s failed
 jsr (%a5)
 move.l %a3,-(%sp)
 pea 1.w
 jmp 0x40124192
failed:
 lea 24(%sp),%sp
 jmp 0x40124046
''')
    current = redirect('kit_dump_current_result', 0x40123c1a,
                       '4e95 2f0c 4878 0001', '''
 tst.b %d0
 beq.s failed
 jsr (%a5)
 move.l %a4,-(%sp)
 pea 1.w
 jmp 0x40123c22
failed:
 lea 28(%sp),%sp
 jmp 0x40124046
''')
    return dict(kit_packet=packet, kit_indexed_result=indexed,
                kit_current_result=current, kit_encoded_bytes=12288)
