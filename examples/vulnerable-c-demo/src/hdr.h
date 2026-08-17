/*
 * hdr.h — header block parser interface for the KavachX C demo target.
 *
 * SECURITY NOTICE: this target contains an INTENTIONALLY SEEDED vulnerability. It exists only as
 * an AddressSanitizer / libFuzzer analysis target for the KavachX proof of concept.
 */

#ifndef KAVACHX_HDR_H
#define KAVACHX_HDR_H

#include <stddef.h>

#define HDR_MAX_SLOTS 8
#define HDR_MAX_KEY 32
#define HDR_MAX_VALUE 64

enum {
    HDR_OK = 0,
    HDR_ERR_ARG = -1,
    HDR_ERR_FORMAT = -2,
    HDR_ERR_KEY = -3,
    HDR_ERR_FULL = -4,
    HDR_ERR_MISSING = -5
};

typedef struct {
    char key[HDR_MAX_KEY];
    char value[HDR_MAX_VALUE];
    int used;
} hdr_slot;

typedef struct {
    hdr_slot slots[HDR_MAX_SLOTS];
    size_t count;
} hdr_block;

void hdr_block_init(hdr_block *block);

/* Parse a KEY:VALUE block. Returns HDR_OK or one of the HDR_ERR_* codes. */
int hdr_parse(const char *raw, size_t raw_len, hdr_block *block);

/* Copy the value for `key` into `out`. Returns HDR_OK or HDR_ERR_MISSING. */
int hdr_lookup(const hdr_block *block, const char *key, char *out, size_t out_cap);

/* Monotonic counter of successful parses — the observable behind a monotonic-counter clause. */
size_t hdr_parse_count(void);

#endif /* KAVACHX_HDR_H */
