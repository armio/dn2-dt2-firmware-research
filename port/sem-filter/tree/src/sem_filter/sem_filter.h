/* Faust-derived Oberheim filter. See LICENSE-STK-4.3.md and README.md. */
#ifndef DN2_SEM_FILTER_H
#define DN2_SEM_FILTER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One instance per voice AND channel. No pointer ownership or heap storage. */
typedef struct {
    float band_state, low_state;
    float sample_rate, smoothing;
    /* prewarped cutoff, 1/Q, LP weight, HP weight, BP weight */
    float current[5], target[5];
    unsigned faults;
} SemFilter;

void sem_filter_init(SemFilter *filter, float sample_rate);
/* Clear both integrators and settle controls immediately at their targets. */
void sem_filter_reset(SemFilter *filter);
/* Cutoff Hz; Q 0.5..10; morph 0=LP, 0.5=notch, 1=HP; BP overrides morph. */
#ifndef SEM_FILTER_NO_LIBM
void sem_filter_set(SemFilter *filter, float cutoff, float q,
                    float morph, int bandpass);
#endif
/* For native coefficient conversion: g=tan(pi*cutoff/sample_rate), damping=1/Q. */
void sem_filter_set_coefficients(SemFilter *filter, float g, float damping,
                                 float morph, int bandpass);
float sem_filter_tick(SemFilter *filter, float input);
void sem_filter_process(SemFilter *filter, float *samples, size_t count);

#ifdef __cplusplus
}
#endif
#endif
