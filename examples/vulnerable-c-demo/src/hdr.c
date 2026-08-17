/*
 * hdr.c — header block parser for the KavachX C demo target.
 *
 * SECURITY NOTICE: this file contains an INTENTIONALLY SEEDED vulnerability. It exists only
 * as an AddressSanitizer / libFuzzer analysis target for the KavachX proof of concept.
 */

#include "hdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SLOT_VALUE_CAP 64

static size_t g_parse_count = 0;

size_t hdr_parse_count(void) { return g_parse_count; }

static void slot_reset(hdr_slot *slot) {
    memset(slot->key, 0, sizeof(slot->key));
    memset(slot->value, 0, sizeof(slot->value));
    slot->used = 0;
}

void hdr_block_init(hdr_block *block) {
    for (size_t i = 0; i < HDR_MAX_SLOTS; ++i) {
        slot_reset(&block->slots[i]);
    }
    block->count = 0;
}

/*
 * Copy one KEY:VALUE line into a slot.
 *
 * SEEDED VULNERABILITY (CWE-787): the value length is measured but never clamped to
 * SLOT_VALUE_CAP before the copy, so a long value writes past slot->value.
 */
static int slot_write(hdr_slot *slot, const char *key, size_t key_len, const char *value,
                      size_t value_len) {
    if (key_len == 0 || key_len >= HDR_MAX_KEY) {
        return HDR_ERR_KEY;
    }
    memcpy(slot->key, key, key_len);
    slot->key[key_len] = '\0';

    /* The bug: value_len comes straight from the input. */
    memcpy(slot->value, value, value_len);
    slot->value[value_len] = '\0';

    slot->used = 1;
    return HDR_OK;
}

int hdr_parse(const char *raw, size_t raw_len, hdr_block *block) {
    if (raw == NULL || block == NULL) {
        return HDR_ERR_ARG;
    }
    hdr_block_init(block);
    g_parse_count += 1;

    size_t line_start = 0;
    for (size_t i = 0; i <= raw_len; ++i) {
        if (i != raw_len && raw[i] != '\n') {
            continue;
        }
        size_t line_len = i - line_start;
        if (line_len == 0) {
            line_start = i + 1;
            continue;
        }
        if (block->count >= HDR_MAX_SLOTS) {
            return HDR_ERR_FULL;
        }

        const char *line = raw + line_start;
        const char *colon = memchr(line, ':', line_len);
        if (colon == NULL) {
            return HDR_ERR_FORMAT;
        }

        size_t key_len = (size_t)(colon - line);
        size_t value_len = line_len - key_len - 1;

        int rc = slot_write(&block->slots[block->count], line, key_len, colon + 1, value_len);
        if (rc != HDR_OK) {
            return rc;
        }
        block->count += 1;
        line_start = i + 1;
    }
    return HDR_OK;
}

int hdr_lookup(const hdr_block *block, const char *key, char *out, size_t out_cap) {
    if (block == NULL || key == NULL || out == NULL || out_cap == 0) {
        return HDR_ERR_ARG;
    }
    for (size_t i = 0; i < block->count; ++i) {
        if (block->slots[i].used && strcmp(block->slots[i].key, key) == 0) {
            snprintf(out, out_cap, "%s", block->slots[i].value);
            return HDR_OK;
        }
    }
    return HDR_ERR_MISSING;
}
