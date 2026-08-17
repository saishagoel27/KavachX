/*
 * fuzz_hdr.c — libFuzzer harness for hdr_parse.
 *
 * Build:  clang -g -O1 -fsanitize=fuzzer,address,undefined -o fuzz_hdr src/fuzz_hdr.c src/hdr.c
 * Run:    ./fuzz_hdr corpus/ -max_total_time=60
 *
 * The seeded overflow is reached by any header line whose value exceeds HDR_MAX_VALUE.
 */

#include "hdr.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    hdr_block block;
    hdr_parse((const char *)data, size, &block);
    return 0;
}
