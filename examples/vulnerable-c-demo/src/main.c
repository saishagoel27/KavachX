/*
 * main.c — CLI entrypoint for the KavachX C demo target.
 *
 * Reads a header block from a file or from stdin, parses it, and prints the result.
 *
 * Exit codes:  0 parsed, 1 parse error, 2 usage error.
 * A heap-buffer-overflow inside hdr_parse aborts under AddressSanitizer, which is the
 * deterministic signal KavachX validates against.
 */

#include "hdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT (1 << 20)

static int read_all(FILE *stream, char *buffer, size_t cap, size_t *out_len) {
    size_t total = 0;
    size_t got;
    while ((got = fread(buffer + total, 1, cap - total - 1, stream)) > 0) {
        total += got;
        if (total >= cap - 1) break;
    }
    buffer[total] = '\0';
    *out_len = total;
    return 0;
}

int main(int argc, char **argv) {
    static char input[MAX_INPUT];
    size_t length = 0;

    if (argc == 2) {
        FILE *file = fopen(argv[1], "rb");
        if (file == NULL) {
            fprintf(stderr, "cannot open %s\n", argv[1]);
            return 2;
        }
        read_all(file, input, sizeof(input), &length);
        fclose(file);
    } else if (argc == 1) {
        read_all(stdin, input, sizeof(input), &length);
    } else {
        fprintf(stderr, "usage: %s [header-file]\n", argv[0]);
        return 2;
    }

    hdr_block block;
    int rc = hdr_parse(input, length, &block);
    if (rc != HDR_OK) {
        fprintf(stderr, "parse error %d\n", rc);
        return 1;
    }

    printf("{\"ok\":true,\"count\":%zu,\"parses\":%zu}\n", block.count, hdr_parse_count());
    for (size_t i = 0; i < block.count; ++i) {
        if (block.slots[i].used) {
            printf("  %s=%s\n", block.slots[i].key, block.slots[i].value);
        }
    }
    return 0;
}
