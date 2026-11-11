/*
 * Oberheim state-variable model: Eric Tarr, Faust ve.oberheim().
 * Cubic soft clipping: Julius O. Smith III, Faust ef.cubicnl().
 * Faust library functions: Copyright (C) 2003-2017 by Julius O. Smith III
 * <jos@ccrma.stanford.edu>, except where noted otherwise (oberheim: Eric Tarr);
 * released under the MIT-style STK-4.3 license below.
 * Scalar C adaptation for DN2, 2026. See README.md for pinned upstream sources.
 *
 * The Synthesis ToolKit in C++ (STK)
 * Copyright (c) 1995--2017 Perry R. Cook and Gary P. Scavone
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "sem_filter.h"
#ifndef SEM_FILTER_NO_LIBM
#include <math.h>
#endif

static float bounded(float value, float lo, float hi, float fallback)
{
    union { float f; unsigned u; } bits;
    bits.f = value;
    /* selcc's SHARC ordered comparisons do not reject unordered NaNs. */
    if ((bits.u & 0x7f800000u) == 0x7f800000u)
        return fallback;
    return value < lo ? lo : value > hi ? hi : value;
}

void sem_filter_reset(SemFilter *filter)
{
    unsigned i;
    filter->band_state = filter->low_state = 0.0f;
    for (i = 0; i < 5; ++i)
        filter->current[i] = filter->target[i];
    filter->faults = 0;
}

void sem_filter_set_coefficients(SemFilter *filter, float g, float damping,
                                 float morph, int bandpass)
{
    morph = bounded(morph, 0.0f, 1.0f, 0.0f);
    filter->target[0] = bounded(g, 0.0f, 6.3137515f, 0.06554346f);
    filter->target[1] = bounded(damping, 0.1f, 2.0f, 1.0f);
    filter->target[2] = bandpass ? 0.0f : (morph <= 0.5f ? 1.0f : 2.0f - 2.0f * morph);
    filter->target[3] = bandpass ? 0.0f : (morph >= 0.5f ? 1.0f : 2.0f * morph);
    filter->target[4] = bandpass ? 1.0f : 0.0f;
}

#ifndef SEM_FILTER_NO_LIBM
void sem_filter_set(SemFilter *filter, float cutoff, float q,
                    float morph, int bandpass)
{
    float max_cutoff = filter->sample_rate * 0.45f;
    if (max_cutoff > 20000.0f)
        max_cutoff = 20000.0f;
    cutoff = bounded(cutoff, 20.0f, max_cutoff, 1000.0f);
    q = bounded(q, 0.5f, 10.0f, 1.0f);
    sem_filter_set_coefficients(filter,
        tanf((3.1415927f / filter->sample_rate) * cutoff),
        1.0f / q, morph, bandpass);
}
#endif

void sem_filter_init(SemFilter *filter, float sample_rate)
{
    filter->sample_rate = bounded(sample_rate, 8000.0f, 192000.0f, 48000.0f);
    /* Upstream wrapper's time constant, applied to g and all audible controls. */
    filter->smoothing = 44.1f / filter->sample_rate;
    /* Normalized default: 1 kHz at 48 kHz. Native callers supply coefficients. */
    sem_filter_set_coefficients(filter, 0.06554346f, 1.0f, 0.0f, 0);
    sem_filter_reset(filter);
}

float sem_filter_tick(SemFilter *filter, float input)
{
    unsigned i;
    union { float f; unsigned u; } input_bits, low_bits, band_bits;
    float g, feedback, denominator, residual, delta, band, gb, low, high;
    input_bits.f = input;
    if ((input_bits.u & 0x7fffffffu) > 0x41800000u) {
        input = bounded(input, -16.0f, 16.0f, 0.0f);
        ++filter->faults;
    }
    for (i = 0; i < 5; ++i)
        filter->current[i] += filter->smoothing * (filter->target[i] - filter->current[i]);
    g = filter->current[0];
    feedback = filter->current[1] + g;
    denominator = g * feedback + 1.0f;
    residual = input - (filter->low_state + filter->band_state * feedback);
    delta = g * residual / denominator;
    band = filter->band_state + delta;
    if (band < -1.0f) band = -1.0f;
    if (band > 1.0f) band = 1.0f;
    band *= 1.0f - 0.33333334f * (band * band);
    gb = g * band;
    low = filter->low_state + gb;
    high = residual / denominator;
    filter->low_state += 2.0f * gb;
    filter->band_state = delta + band;
    low_bits.f = filter->low_state;
    band_bits.f = filter->band_state;
    if ((low_bits.u & 0x7fffffffu) > 0x49742400u ||
        (band_bits.u & 0x7fffffffu) > 0x49742400u) {
        filter->low_state = filter->band_state = 0.0f;
        ++filter->faults;
        return 0.0f;
    }
    return filter->current[2] * low + filter->current[3] * high + filter->current[4] * band;
}

void sem_filter_process(SemFilter *filter, float *samples, size_t count)
{
    size_t i;
    float band_state = filter->band_state, low_state = filter->low_state;
    float g = filter->current[0], damping = filter->current[1];
    float lp = filter->current[2], hp = filter->current[3], bp = filter->current[4];
    const float alpha = filter->smoothing;
    const float tg = filter->target[0], td = filter->target[1];
    const float tlp = filter->target[2], thp = filter->target[3], tbp = filter->target[4];
    unsigned faults = filter->faults;
    /* Keep histories in locals and expand the five fixed controls explicitly.
     * selcc does not inline tick() or unroll the generic control loop. */
    for (i = 0; i < count; ++i) {
        union { float f; unsigned u; } input_bits, low_bits, band_bits;
        float input = samples[i];
        float feedback, denominator, residual, reciprocal, delta, band, gb, low, high;
        input_bits.f = input;
        if ((input_bits.u & 0x7fffffffu) > 0x41800000u) {
            input = bounded(input, -16.0f, 16.0f, 0.0f);
            ++faults;
        }
        g += alpha * (tg - g);
        damping += alpha * (td - damping);
        lp += alpha * (tlp - lp);
        hp += alpha * (thp - hp);
        bp += alpha * (tbp - bp);
        feedback = damping + g;
        denominator = g * feedback + 1.0f;
        residual = input - (low_state + band_state * feedback);
        reciprocal = 1.0f / denominator;
        high = residual * reciprocal;
        delta = g * high;
        band = band_state + delta;
        if (band < -1.0f) band = -1.0f;
        if (band > 1.0f) band = 1.0f;
        band *= 1.0f - 0.33333334f * (band * band);
        gb = g * band;
        low = low_state + gb;
        low_state += 2.0f * gb;
        band_state = delta + band;
        low_bits.f = low_state;
        band_bits.f = band_state;
        if ((low_bits.u & 0x7fffffffu) > 0x49742400u ||
            (band_bits.u & 0x7fffffffu) > 0x49742400u) {
            low_state = band_state = 0.0f;
            ++faults;
            samples[i] = 0.0f;
        } else {
            samples[i] = lp * low + hp * high + bp * band;
        }
    }
    filter->band_state = band_state;
    filter->low_state = low_state;
    filter->current[0] = g;
    filter->current[1] = damping;
    filter->current[2] = lp;
    filter->current[3] = hp;
    filter->current[4] = bp;
    filter->faults = faults;
}
