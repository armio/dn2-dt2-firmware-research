"""A small sample bank baked into section 7, behind a directory (our own format).

The shape is Waverider Milestone 4's wavetable directory, for samples:

    DM BANK_DM   +0  magic 'OSB1' (0x3142534f)
                 +4  count
                 +8  entry[0]: pointer (DM byte address), length (samples), rate (Hz)
                 +20 entry[1] ...
    then the samples, int16 little-endian, each entry's pointer 4-byte aligned.
    Each sample has loaded zero guards before and after its PCM. Directory
    pointers address the PCM, and lengths exclude guards and alignment padding.

The adapter resolves a voice's SAMP through it and never trusts a slot at or
past the count (it plays slot 0). Without the magic it renders nothing.
"""

from __future__ import annotations

import struct

MAGIC = 0x3142534F          # b'OSB1' as a little-endian word
HEADER = 8
ENTRY = 12
BYTES_PER_SAMPLE = 2
GUARD_SAMPLES = 2048
GUARD_BYTES = GUARD_SAMPLES * BYTES_PER_SAMPLE
# The donor render can read beyond its logical end during a 64-point block.
# At TUNE 127, ~19.03 source samples/point * 64, plus its 141-sample minimum
# span and six-tap reach, fits inside 2048 samples. Guard both directions even
# when the adapter clamps the logical playback bounds.


def build(base: int, samples: list[list[int]], rate: int = 48000, limit: int | None = None
          ) -> tuple[bytes, list[dict]]:
    """Return loaded bytes and logical entries; limit includes all zero guards.

    Empty PCM is invalid because the adapter uses length - 1. Short nonempty
    samples retain their exact length; playback bounds belong to the adapter.
    """
    body_start = (base + HEADER + ENTRY * len(samples) + 3) & ~3
    at = body_start
    entries, body = [], bytearray()
    guard = b"\0" * GUARD_BYTES
    for slot, pcm in enumerate(samples):
        if not pcm:
            raise ValueError(f"sample {slot} is empty")
        entries.append({"pointer": at + GUARD_BYTES, "length": len(pcm), "rate": rate})
        chunk = struct.pack(f"<{len(pcm)}h", *pcm)
        chunk += b"\0" * (-len(chunk) % 4)
        body.extend(guard)
        body.extend(chunk)
        body.extend(guard)
        at += 2 * GUARD_BYTES + len(chunk)
    head = struct.pack("<II", MAGIC, len(samples))
    for e in entries:
        head += struct.pack("<III", e["pointer"], e["length"], e["rate"])
    head += b"\0" * (body_start - base - len(head) if entries else 0)
    data = head + body
    if limit is not None and len(data) > limit:
        raise ValueError(f"the bank is {len(data):,} bytes; the span holds {limit:,}")
    return data, entries
