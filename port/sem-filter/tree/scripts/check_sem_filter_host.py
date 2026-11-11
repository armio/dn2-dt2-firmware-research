#!/usr/bin/env python3
"""Compare the C SEM port with pinned, unchanged Faust-generated C++ and stress state handling."""
import argparse
import ctypes as C
import hashlib
import json
import math
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src/sem_filter'


class State(C.Structure):
    _fields_ = [('band_state', C.c_float), ('low_state', C.c_float),
                ('sample_rate', C.c_float), ('smoothing', C.c_float),
                ('current', C.c_float * 5), ('target', C.c_float * 5),
                ('faults', C.c_uint)]


def run(out):
    out.mkdir(parents=True, exist_ok=True)
    wrapper = out / 'reference_wrapper.cpp'
    wrapper.write_text('''#include "Oberheim.cpp"
extern "C" {
void reference_constant(float rate, float cutoff, float q, const float *input,
                        float *notch, float *band, float *high, float *low, int count) {
    mydsp filter;
    filter.init((int)rate);
    filter.fHslider0 = cutoff;
    filter.fHslider1 = q;
    // Hold cutoff settled: compare the signal recurrence, not wrapper smoothing.
    filter.fConst1 = 0.0f;
    filter.fConst2 = 1.0f;
    filter.fRec6[0] = filter.fRec6[1] = cutoff;
    float *inputs[] = {const_cast<float *>(input)};
    float *outputs[] = {notch, band, high, low};
    filter.compute(count, inputs, outputs);
}
}
''')
    obj, lib = out / 'sem_filter.o', out / ('sem_filter.dylib' if sys.platform == 'darwin' else 'sem_filter.so')
    common = ['-O2', '-ffp-contract=off', '-fPIC', '-Wall', '-Wextra', '-Werror']
    subprocess.run(['cc', '-std=c99', *common, '-c', str(SRC/'sem_filter.c'), '-o', str(obj)], check=True)
    subprocess.run(['c++', '-std=c++11', '-O2', '-ffp-contract=off', '-fPIC', '-shared',
                    '-I'+str(SRC/'reference'), str(wrapper), str(obj), '-o', str(lib)], check=True)
    api = C.CDLL(str(lib))
    pointer = C.POINTER(C.c_float)
    api.sem_filter_init.argtypes = [C.POINTER(State), C.c_float]
    api.sem_filter_reset.argtypes = [C.POINTER(State)]
    api.sem_filter_set.argtypes = [C.POINTER(State), C.c_float, C.c_float, C.c_float, C.c_int]
    api.sem_filter_set_coefficients.argtypes = [C.POINTER(State), C.c_float, C.c_float, C.c_float, C.c_int]
    api.sem_filter_process.argtypes = [C.POINTER(State), pointer, C.c_size_t]
    api.sem_filter_tick.argtypes = [C.POINTER(State), C.c_float]
    api.sem_filter_tick.restype = C.c_float
    api.reference_constant.argtypes = [C.c_float, C.c_float, C.c_float, pointer, pointer, pointer, pointer, pointer, C.c_int]

    def state(rate=48000.0, cutoff=1000.0, q=1.0, morph=0.0, bp=0):
        s = State()
        api.sem_filter_init(C.byref(s), rate)
        api.sem_filter_set(C.byref(s), cutoff, q, morph, bp)
        api.sem_filter_reset(C.byref(s))
        return s

    def process(s, data):
        a = (C.c_float * len(data))(*data)
        api.sem_filter_process(C.byref(s), a, len(a))
        return list(a)

    rng = random.Random(0x53454d)
    n = 4096
    data = [0.65 * math.sin(2*math.pi*377*i/48000) + rng.uniform(-0.4, 0.4) for i in range(n)]
    data[0] = 4.0
    input_buf = (C.c_float*n)(*data)
    reference_cases = []
    for rate in (44100, 48000, 96000):
        for cutoff in (20, 300, 5000, min(20000, 0.45*rate)):
            for q in (0.5, 2, 10):
                refs = [(C.c_float*n)() for _ in range(4)]
                api.reference_constant(rate, cutoff, q, input_buf, *refs, n)
                for label, morph, bp, index in [('LP',0,0,3), ('NOTCH',0.5,0,0), ('HP',1,0,2), ('BP',0,1,1)]:
                    s = state(rate, cutoff, q, morph, bp)
                    actual = process(s, data)
                    error = max(abs(a-b) for a,b in zip(actual, refs[index]))
                    assert error < 5e-5, (rate, cutoff, q, label, error)
                    assert s.faults == 0, (rate, cutoff, q, label, s.faults)
                    reference_cases.append(dict(rate=rate, cutoff=cutoff, q=q, mode=label, max_error=error))

    # A control update must keep integrators; reset must remove their entire tail.
    s = state()
    process(s, [1.0]+[0.0]*31)
    history = (s.band_state, s.low_state)
    api.sem_filter_set(C.byref(s), 19000, 10, 1, 1)
    assert history == (s.band_state, s.low_state)
    assert any(abs(x) > 1e-10 for x in process(s, [0.0]*32))
    api.sem_filter_reset(C.byref(s))
    assert process(s, [0.0]*256) == [0.0]*256

    # Block boundaries and unrelated channel activity cannot affect a voice.
    full, split, other = state(), state(), state(cutoff=6000, q=9, bp=1)
    expected = process(full, data)
    actual = []
    cursor = 0
    for count in [1, 31, 7, 25, 255, 3, 1024, 2750]:
        chunk = data[cursor:cursor+count]
        actual += process(split, chunk)
        process(other, [rng.uniform(-4,4) for _ in chunk])
        cursor += len(chunk)
    assert cursor == len(data) and actual == expected

    # Optimized block loop and scalar tick retain the same model/modulation.
    block_state, tick_state = state(), state()
    tick_error = 0.0
    for block in range(16):
        cutoff, q, morph, bp = 20*(1000**rng.random()), rng.uniform(0.5,10), rng.random(), block%4==0
        for s in (block_state,tick_state):
            api.sem_filter_set(C.byref(s),cutoff,q,morph,bp)
        chunk=data[block*32:(block+1)*32]
        actual=process(block_state,chunk)
        ticks=[api.sem_filter_tick(C.byref(tick_state),value) for value in chunk]
        tick_error=max(tick_error,max(abs(a-b) for a,b in zip(actual,ticks)))
    assert tick_error < 2e-5,tick_error

    # Adversarial control changes, hot audio and all output modes.
    stress_cases = []
    for rate in (8000, 44100, 48000, 96000, 192000):
        s = state(rate)
        peak = 0.0
        for block in range(1000):
            cutoff = 20.0 * (1000.0 ** rng.random())
            q = rng.uniform(0.5, 10)
            api.sem_filter_set(C.byref(s), cutoff, q, rng.random(), block % 7 == 0)
            values = process(s, [rng.uniform(-8, 8) for _ in range(32)])
            assert all(math.isfinite(v) for v in values)
            peak = max(peak, max(map(abs, values)))
        assert s.faults == 0, (rate, s.faults)
        stress_cases.append(dict(rate=rate, blocks=1000, peak=peak, faults=s.faults))

    # Boundary sanitization: NaN/Inf controls, input and corrupted DSP history.
    s = state()
    for bad in (float('nan'), float('inf'), -float('inf'), 1e30, -1e30):
        api.sem_filter_set(C.byref(s), bad, bad, bad, 0)
        assert all(math.isfinite(v) for v in s.target)
        api.sem_filter_set_coefficients(C.byref(s), bad, bad, bad, 1)
        assert all(math.isfinite(v) for v in s.target)
        assert all(math.isfinite(v) for v in process(s, [bad]+[0.0]*31))
    for field in ('band_state', 'low_state'):
        setattr(s, field, float('nan'))
        assert math.isfinite(api.sem_filter_tick(C.byref(s), 0.0))
        assert s.band_state == 0 and s.low_state == 0
    assert s.faults > 0

    # Reinitializing used state equals a fresh instance (no stale voice memory).
    api.sem_filter_init(C.byref(s), 48000)
    fresh = State()
    api.sem_filter_init(C.byref(fresh), 48000)
    assert bytes(s) == bytes(fresh)
    report = dict(status='PASS', state_bytes=C.sizeof(State),
                  reference_cases=len(reference_cases), reference_max_error=max(x['max_error'] for x in reference_cases),
                  reference=reference_cases, modulation=stress_cases,
                  reset=True, block_partition=True, stereo_isolation=True, invalid_input_recovery=True,
                  scalar_tick_max_error=tick_error,
                  sources={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
                           (SRC/'sem_filter.c',SRC/'sem_filter.h',SRC/'reference/Oberheim.cpp',SRC/'reference/Oberheim.hpp')},
                  limits=['Host numerical checks only; no SHARC timing or hardware audio claim.',
                          'Reference comparison holds cutoff settled; g smoothing intentionally differs from upstream Hz smoothing.'])
    (out/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('reference','sources')}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    run(parser.parse_args().out.resolve())
