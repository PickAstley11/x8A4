#ifndef X8A4_INTERNAL_STATE_H
#define X8A4_INTERNAL_STATE_H

#include <stdint.h>

/* Internal process-local caches shared across x8A4 implementation files. */
extern int nonce_slot_format_cached;
extern int verbose_cached;
extern uint64_t *gc_cached;
extern int gc_count_cached;
extern uint64_t *gc_d_cached;
extern int gc_d_count_cached;

void x8A4_detect_nonce_format(void);

#endif /* X8A4_INTERNAL_STATE_H */
