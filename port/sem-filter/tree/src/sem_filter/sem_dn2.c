/* Native DN2 OS 1.11 control adapter for the Faust-derived SEM kernel.
 * Original integration code, 2026. The filter retains its STK-4.3 notices.
 */
#include "sem_dn2.h"

#define SEM_ACTIVE 0x53454d31u

static float normalized(float value)
{
    union { float f; unsigned u; } bits;
    bits.f = value;
    if ((bits.u & 0x7f800000u) == 0x7f800000u || value < 0.0f)
        return 0.0f;
    return value > 1.0f ? 1.0f : value;
}

void sem_dn2_process(SemDn2Slot *slot, float *samples, unsigned count)
{
    /* Native MULTIMODE coefficient table. Its setter uses the same 1024x
     * normalized cutoff lookup after keytracking, envelope and modulation.
     * This address must be preimage-checked in the R023 DSP builder.
     */
    const float *cutoff_table = (const float *)0x26d3c0u;
    float position = normalized(slot->cutoff) * 1024.0f;
    unsigned index;
    float g, q, mode;
    int bandpass;
    unsigned fresh = slot->active != SEM_ACTIVE;
    if (count > 32u) return;
    if (position > 1023.0f) position = 1023.0f;
    index = (unsigned)position;
    g = cutoff_table[index];
    if (index < 1023u)
        g += (position-(float)index) * (cutoff_table[index+1u]-g);
    /* Native RESO is divided by 128; its highest user value is 127. */
    q = 0.5f + 9.5f * normalized(slot->resonance * (128.0f/127.0f));
    mode = normalized(slot->mode) * 127.0f;
    bandpass = mode >= 126.5f;
    if (fresh) sem_filter_init(&slot->filter, 48000.0f);
    sem_filter_set_coefficients(&slot->filter, g, 1.0f/q, mode/126.0f, bandpass);
    if (fresh) {
        sem_filter_reset(&slot->filter);
        slot->active = SEM_ACTIVE;
    }
    sem_filter_process(&slot->filter, samples, count);
}
