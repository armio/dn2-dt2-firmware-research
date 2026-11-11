"""R026 SEM graph: float reference, firmware integer model and tables (docs/DN2-R026-SEM-GRAPH-SPEC.md).

Rows are image rows of the 128x64 cell (bitmap y = 63 - row). Columns 22..70 show FREQ positions
(x - 22) * 128 / 48 of the native cutoff table; row = 48 - log2 |H|^2, clipped to 41..55.
Inputs are the native graph arguments: TYPE 0..127, FREQ raw 0..32767, RESO raw 0..32767.
"""
import hashlib
import math
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DSP = ROOT/'output/dn2-research/r025-right-gate-20261109/dsp/section_7.bin'
DSP_SHA = '1b858714c2ef1322bdfa44b7c8ce2fff14204967a1845e6f81c4b019a52d724f'
TABLE_ADDRESS, TABLE_SHA = 0x2826d3c0, 'a7d139880e0bbe8e116e99fa5fe5a529cf28f7dccc1e886ded4543395f175258'
COLUMNS = tuple(range(22, 71))
PASSBAND, TOP, FLOOR = 48, 41, 55
CLAMP = 6*256          # exponentials saturate 6 octaves from the cutoff (Q8 octaves)
G_MAX = 6.3137515      # sem_filter_set_coefficients bound: the kernel's cutoff stops at 21.6 kHz


def cutoff_table(dsp=DSP):
    """The 1024 prewarped coefficients g = tan(pi f / fs) the DSP interpolates; pinned image and table."""
    raw = Path(dsp).read_bytes()
    if hashlib.sha256(raw).hexdigest() != DSP_SHA:
        raise ValueError('unexpected DSP image for the SEM graph tables')
    import build_dn2_sem_dsp as S
    k = S.C.M.Digikit(S.C.SRC/'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    table = S.B.decode_view(k, raw).read(TABLE_ADDRESS, 4096)
    if hashlib.sha256(table).hexdigest() != TABLE_SHA:
        raise ValueError('native cutoff table changed')
    return struct.unpack('<1024f', table)


def g_at(g, raw):
    """DSP lookup (sem_dn2.c): position raw/32 over 1024 entries, linear interpolation, capped at 1023."""
    pos = min(1023.0, raw/32)
    i = int(pos)
    return g[i] if i >= 1023 else g[i] + (pos-i)*(g[i+1]-g[i])


def cutoff_g(g, raw):
    """Coefficient the kernel actually runs at: the table lookup, bounded like sem_filter.c."""
    return min(G_MAX, g_at(g, raw))


def column_raw(x):
    return (x-22)*32768/48


def rounded_row(value):
    return max(TOP, min(FLOOR, math.floor(value + 0.5)))


# ---------------------------------------------------------------- float reference

def weights(t):
    if t >= 127:
        return 0.0, 0.0, 1.0
    m = t/126
    return min(1.0, 2-2*m), min(1.0, 2*m), 0.0


def q_of(r):
    return 0.5 + 9.5*min(1.0, r/32512)


def response(g, t, f, r, gx):
    """|H|^2 of the kernel's linear response at coefficient gx (sem_filter.c output weights, TPT SVF)."""
    wl, wh, wb = weights(t)
    q = q_of(r)
    s = 1j*gx/cutoff_g(g, min(f, 32767))
    return abs((wl + wh*s*s + wb*s)/(s*s + s/q + 1))**2


def reference(g, t, f, r):
    """(rows, forced) per spec section 2; forced = {'cutoff': i, 'notch': i (when drawn)}."""
    f, r = min(f, 32767), min(r, 32767)
    wl, wh, wb = weights(t)
    q = q_of(r)
    lc = math.log2(cutoff_g(g, f))
    lx = [math.log2(g_at(g, column_raw(x))) for x in COLUMNS]
    rows = []
    for l in lx:
        h2 = response(g, t, f, r, 2**l)
        rows.append(FLOOR if h2 == 0 else rounded_row(PASSBAND - math.log2(h2)))
    ic = min(range(len(lx)), key=lambda i: abs(lx[i]-lc))
    peak = q*q if wb else (wl-wh)**2*q*q
    rows[ic] = FLOOR if peak == 0 else rounded_row(PASSBAND - math.log2(peak))
    forced = {'cutoff': ic}
    if wl > 0 and wh > 0:
        l0 = lc + 0.5*math.log2(wl/wh)
        if lx[0] <= l0 <= lx[-1]:
            forced['notch'] = min(range(len(lx)), key=lambda i: abs(lx[i]-l0))
            rows[forced['notch']] = FLOOR
    return rows, forced


# ---------------------------------------------------------------- integer model (the firmware, line for line)

def tables(g):
    """Firmware tables: LT (129 x s16, Q8 log2 of the bounded cutoff g at coarse FREQ), LX (49 x s16, per column),
    E (64 x u16, 2^(k/64) Q15), LOGM (32 x u8, log2(1+k/32) Q8)."""
    lt = [round(256*math.log2(cutoff_g(g, k*256))) for k in range(129)]
    lx = [round(256*math.log2(g_at(g, column_raw(x)))) for x in COLUMNS]
    e = [round(32768*2**(k/64)) for k in range(64)]
    logm = [round(256*math.log2(1+k/32)) for k in range(32)]
    assert all(-32768 <= v < 32768 for v in lt+lx) and max(e) < 65536 and max(logm) < 256
    assert all(a <= b for a, b in zip(lt, lt[1:])) and all(a < b for a, b in zip(lx, lx[1:]))
    return dict(LT=lt, LX=lx, E=e, LOGM=logm)


def table_bytes(tb):
    return (struct.pack('>129h', *tb['LT']) + struct.pack('>49h', *tb['LX']) +
            struct.pack('>64H', *tb['E']) + bytes(tb['LOGM']))


def exp2_q9(tb, d):
    """2^(d/256) in Q9 for |d| <= CLAMP."""
    k = (d & 255) >> 2
    shift = (d >> 8) - 6
    return tb['E'][k] << shift if shift >= 0 else tb['E'][k] >> -shift


def log2_q8(tb, v):
    """log2(v) in Q8 for 0 < v < 2^31: top bit by five compares, five mantissa bits."""
    p = 0
    for b in (16, 8, 4, 2, 1):
        if v >> (p+b):
            p += b
    k = (v >> (p-5)) & 31 if p >= 5 else (v << (5-p)) & 31
    return (p << 8) + tb['LOGM'][k]


def model_row(tb, num, den):
    if num == 0:
        return FLOOR
    return max(TOP, min(FLOOR, PASSBAND - ((log2_q8(tb, num) - log2_q8(tb, den) + 128) >> 8)))


def model(tb, t, f, r):
    """(rows, forced) as the firmware computes them."""
    t, f, r = t & 127, f & 32767, min(r & 32767, 32512)
    bp = t == 127
    tt = (t*4161 + 512) >> 10                       # 2m in Q8, rounded
    wl = 0 if bp else min(256, 512-tt)
    wh = 0 if bp else min(256, tt)
    q8 = 128 + ((r*4902) >> 16)                     # Q in Q8
    iq = (1 << 20)//q8                              # 1/Q in Q12 (divu.w)
    iq2 = (iq*iq) >> 6                              # 1/Q^2 in Q18
    lt = tb['LT']
    k, fr = f >> 8, f & 255
    lc = lt[k] + (((lt[k+1]-lt[k])*fr) >> 8)
    rows, offsets = [], []
    for lx in tb['LX']:
        dr = lx - lc
        offsets.append(dr)
        d = max(-CLAMP, min(CLAMP, dr))
        w, iw = exp2_q9(tb, d), exp2_q9(tb, -d)
        s = w - iw
        den = s*s + iq2
        n = (wl*iw - wh*w) >> 8
        assert 0 < den < 1 << 31 and n*n < 1 << 31    # 32-bit muls.l products in the firmware
        rows.append(model_row(tb, 1 << 18 if bp else n*n, den))
    ic = min(range(len(offsets)), key=lambda i: abs(offsets[i]))
    n = (wl-wh)*2                                   # w = iw = 1.0 (Q9)
    rows[ic] = model_row(tb, 1 << 18 if bp else n*n, iq2)
    forced = {'cutoff': ic}
    if wl and wh:
        d0 = (log2_q8(tb, wl) - log2_q8(tb, wh)) >> 1
        if offsets[0] <= d0 <= offsets[-1]:
            forced['notch'] = min(range(len(offsets)), key=lambda i: abs(offsets[i]-d0))
            rows[forced['notch']] = FLOOR
    return rows, forced


def segments(rows):
    """Native line calls (x0, y0, x1, y1) in bitmap coordinates, left to right."""
    return [(x, 63-a, x+1, 63-b) for x, a, b in zip(COLUMNS, rows, rows[1:])]


def compare(ref, mod):
    """Spec section 3 tolerance between float reference and integer model. Returns a list of problems."""
    (a, fa), (b, fb) = ref, mod
    problems = []
    edge = {0, 1, len(COLUMNS)-2, len(COLUMNS)-1}
    for key in ('cutoff', 'notch'):
        if key in fa and key in fb:
            if abs(fa[key]-fb[key]) > 1:
                problems.append(f'{key} column {fa[key]} vs {fb[key]}')
        elif key in fa or key in fb:
            column = fa.get(key, fb.get(key))
            if column not in edge:
                problems.append(f'{key} drawn by one model only at column {column}')
    near = {i+o for i in list(fa.values())+list(fb.values()) for o in (-1, 0, 1)}
    for i, (x, y) in enumerate(zip(a, b)):
        if i not in near and abs(x-y) > 1:
            problems.append(f'column {i}: {x} vs {y}')
    overwritten = fa.get('notch') == fa['cutoff'] or fb.get('notch') == fb['cutoff']
    if not overwritten and abs(a[fa['cutoff']]-b[fb['cutoff']]) > 1:
        problems.append(f"cutoff value {a[fa['cutoff']]} vs {b[fb['cutoff']]}")
    return problems
