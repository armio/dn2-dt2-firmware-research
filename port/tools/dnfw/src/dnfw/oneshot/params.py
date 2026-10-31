"""From the DT2's own parameter values to a DT2-shaped voice record: the adapter's arithmetic.

`csrc/oneshot/sharc/oneshot5.asm` does exactly this on the DSP; the gate compares
the record it writes with `record_fields` word for word.

**The values are the Digitakt II's records' own** (`dnfw.transplant.oneshot_cf`):
the ColdFire carries the DT2 records transplanted, so a ONESHOT track's machine
slots hold what the DT2's page writes, and the DN2 frame carries machine slots
25..65 verbatim at byte offset `2 * (slot - 25)` of the track's frame slot:

| | slot | frame offset | the value | read as |
|---|---|---|---|---|
| TUNE | 25 | +0 | 4..124 coarse, 64 = the sample's pitch (`0x7c00` max) | `value >> 8` |
| PLAY | 26 | +2 | 0 REV, 1 REV.L, 2 FWD.L, 3 FWD (the DT2 formatter's order) | `value >> 8` |
| SAMP | 28 | +6 | 0..1023, **not** 8.8 (range `0x3ff`, formatter `%d` of the raw value) | whole |
| STRT | 31 | +12 | 8.8, `0x7800` = 120.00 = the end | whole |
| LEN  | 32 | +14 | 8.8, `0x7800` = the whole sample | whole |
| LOOP | 33 | +16 | 0 = OFF; else `value - 1` in 8.8, as STRT | whole |

(#133's first adapter read slots 25..30 coarse and PLAY as `bit 0 reverse, bit
1 loop`: right for its hand-made frames, wrong for the DT2's records, which put
SAMP at 28 and number PLAY the other way.)

**The frame carries the native 16-bit values.** The September 30 instrument
measurement in `dnfw.waverider.frame` corrected the earlier half-scale
assumption: emulator snapshots had been sampled while the parameter mirrors
were still gliding toward their targets. TUNE and PLAY use `frame >> 8`,
STRT / LEN / LOOP keep their native 8.8 scale, and SAMP is the whole frame word.
TUNE fine bytes and machine-page LEV/CFADE remain outside this adapter's scope.

LOOP = OFF is read as "loop from the start" in the looping modes. How the DT2's
own DSP maps OFF is not known -- its frame unpack was not transplanted -- so that
reading is ours [D].
"""

from __future__ import annotations

import struct

from . import record as R

INDICES = {"TUNE": 25, "PLAY": 26, "SAMP": 28, "STRT": 31, "LEN": 32, "LOOP": 33}
COARSE = {"TUNE", "PLAY"}
PLAY_MODES = {"REVERSE": 0, "REVERSE LOOP": 1, "FORWARD LOOP": 2, "FORWARD": 3}
TUNE_CENTRE = 64
FULL = 0x7800                    # 120.00: STRT / LEN / LOOP at the sample's end
MIN_SPAN = 141                   # donor render clamps narrower spans to this
RECIPROCAL = 2185                # 65536 / 30: (x >> 10) * 2185 >> 16 is x / 30720


def frame_offset(name: str) -> int:
    """Byte offset of NAME inside a track's frame slot."""
    return 2 * (INDICES[name] - 25)


def play_mode(play: int) -> tuple[bool, bool]:
    """-> (reverse, loop) for the DT2's PLAY value."""
    return play < 2, play in (1, 2)


def step(tune: int, reverse: bool) -> int:
    """Q31 speed for coarse TUNE (64 = the sample's own pitch). A 48 kHz sample plays
    in the render's 96 kHz domain at half a sample a point; reverse is negative."""
    s = round(0.5 * 2 ** ((tune - TUNE_CENTRE) / 12) * R.Q31)
    return -s if reverse else s


def step_table() -> bytes:
    """256 entries of (lo, hi): [tune] forward, [128 + tune] reverse. Our own numbers."""
    out = b""
    for rev in (False, True):
        for c in range(128):
            out += struct.pack("<q", step(c, rev))
    return out


def scale(value: int, length: int) -> int:
    """VALUE (8.8, 0x7800 = the end) of LENGTH samples, as the adapter computes it."""
    return (((value * length) >> 10) * RECIPROCAL) >> 16


def scale_frame(word: int, length: int) -> int:
    """A native 8.8 frame word of LENGTH samples, in the adapter's integer order."""
    return scale(word, length)


def positions(length: int, strt: int, len_: int, loop: int) -> tuple[int, int, int]:
    """(start, end, loop start), from native STRT, LEN and LOOP frame words."""
    if length < MIN_SPAN:
        raise ValueError("sample is shorter than donor minimum render span")
    fs, fl, fp = (min(v, FULL) for v in (strt, len_, loop))
    s = min(scale_frame(fs, length), length - MIN_SPAN)
    e = max(min(s + scale_frame(fl, length), length), s + MIN_SPAN)
    p = scale(max(fp - 1, 0), length)
    if fp == 0 or p > e - MIN_SPAN:
        p = s
    return s, e, p


def record_fields(*, pointer: int, length: int, tune: int, play: int, strt: int, len_: int,
                  loop: int) -> bytes:
    """The record the adapter writes on a trigger (all other words zero). TUNE and PLAY
    are coarse; STRT, LEN and LOOP whole 16-bit values."""
    s, e, p = positions(length, strt, len_, loop)
    tune, play = min(tune, 127), min(play, 3)
    reverse, looped = play_mode(play)
    rec = bytearray(R.RECORD_BYTES)
    struct.pack_into("<I", rec, R.SAMPLE_PTR, pointer)
    struct.pack_into("<II", rec, R.LENGTH, length, 0)
    R.put_q31(rec, R.LOOP_START, p << 31)
    R.put_q31(rec, R.START, s << 31)
    R.put_q31(rec, R.END, e << 31)
    R.put_q31(rec, R.STEP, step(tune, reverse))
    R.put_q31(rec, R.PHASE, ((e - 1) if reverse else s) << 31)
    rec[R.ACTIVE] = 1
    rec[R.REVERSE] = int(reverse)
    rec[R.LOOP] = int(looped)
    return bytes(rec)


def sound_words(*, tune: int, play: int, samp: int, strt: int, len_: int, loop: int) -> dict[int, int]:
    """The 16-bit slot values a ONESHOT sound holds for these settings: slot -> value."""
    return {25: tune << 8, 26: play << 8, 28: samp, 31: strt, 32: len_, 33: loop}


def frame_words(**settings) -> dict[int, int]:
    """Native transmitted slot words, without the obsolete snapshot halving."""
    return sound_words(**settings)


def frame_settings(words: dict[int, int]) -> dict[str, int]:
    """Decode the native u16 slot words exactly as the corrected adapter does.

    This interface accepts captured words directly, without synthesizing a
    sound or scaling a fixture. Fine TUNE/PLAY bytes are deliberately ignored.
    """
    values = {}
    for name, slot in INDICES.items():
        value = words[slot]
        if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
            raise ValueError(f"frame slot {slot} is not a u16 word")
        values[name] = value
    return {"tune": min((values["TUNE"] >> 8) & 0xFF, 127),
            "play": min((values["PLAY"] >> 8) & 0xFF, 3),
            "samp": values["SAMP"], "strt": min(values["STRT"], FULL),
            "len_": min(values["LEN"], FULL), "loop": min(values["LOOP"], FULL)}


def bank_slot(samp: int, count: int) -> int:
    """The whole SAMP frame word selects a bank slot; out-of-range selects 0."""
    return samp if samp < count else 0
