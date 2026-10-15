#ifndef X8A4_KRW_READ_H
#define X8A4_KRW_READ_H

#include <stddef.h>
#include <stdint.h>

/* x8A4 imports only these read-only libkrw operations. */
int kbase(uint64_t *addr);
int kread(uint64_t from, void *to, size_t len);

#endif /* X8A4_KRW_READ_H */
