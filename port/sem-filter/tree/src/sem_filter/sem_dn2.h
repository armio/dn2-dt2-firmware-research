#ifndef DN2_SEM_ADAPTER_H
#define DN2_SEM_ADAPTER_H
#include "sem_filter.h"

/* Fixed 128-byte slot; assembler offsets are checked by the host test. */
typedef struct {
    SemFilter filter;
    unsigned reserved;
    float cutoff, resonance, mode;
    unsigned active;
    unsigned padding[12];
} SemDn2Slot;

void sem_dn2_process(SemDn2Slot *slot, float *samples, unsigned count);
#endif
