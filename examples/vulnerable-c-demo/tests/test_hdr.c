/* Behavioural tests for the C demo target. These pass on the vulnerable code and must still
 * pass after a patch — that is what differential replay checks for regression. */

#include "../src/hdr.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_single_header(void) {
    const char *raw = "x-trace-id:9f2a\n";
    hdr_block block;
    assert(hdr_parse(raw, strlen(raw), &block) == HDR_OK);
    assert(block.count == 1);
    char out[HDR_MAX_VALUE];
    assert(hdr_lookup(&block, "x-trace-id", out, sizeof(out)) == HDR_OK);
    assert(strcmp(out, "9f2a") == 0);
}

static void test_three_headers(void) {
    const char *raw = "a:1\nb:2\nc:3\n";
    hdr_block block;
    assert(hdr_parse(raw, strlen(raw), &block) == HDR_OK);
    assert(block.count == 3);
}

static void test_slot_capacity(void) {
    const char *raw = "a:1\nb:2\nc:3\nd:4\ne:5\nf:6\ng:7\nh:8\n";
    hdr_block block;
    assert(hdr_parse(raw, strlen(raw), &block) == HDR_OK);
    assert(block.count == HDR_MAX_SLOTS);
}

static void test_too_many_headers_is_rejected(void) {
    const char *raw = "a:1\nb:2\nc:3\nd:4\ne:5\nf:6\ng:7\nh:8\ni:9\n";
    hdr_block block;
    assert(hdr_parse(raw, strlen(raw), &block) == HDR_ERR_FULL);
}

static void test_malformed_line_is_rejected(void) {
    const char *raw = "not-a-header\n";
    hdr_block block;
    assert(hdr_parse(raw, strlen(raw), &block) == HDR_ERR_FORMAT);
}

static void test_missing_key(void) {
    const char *raw = "a:1\n";
    hdr_block block;
    assert(hdr_parse(raw, strlen(raw), &block) == HDR_OK);
    char out[HDR_MAX_VALUE];
    assert(hdr_lookup(&block, "absent", out, sizeof(out)) == HDR_ERR_MISSING);
}

static void test_parse_counter_is_monotonic(void) {
    const char *raw = "a:1\n";
    hdr_block block;
    size_t before = hdr_parse_count();
    hdr_parse(raw, strlen(raw), &block);
    assert(hdr_parse_count() == before + 1);
}

int main(void) {
    test_single_header();
    test_three_headers();
    test_slot_capacity();
    test_too_many_headers_is_rejected();
    test_malformed_line_is_rejected();
    test_missing_key();
    test_parse_counter_is_monotonic();
    printf("all C target tests passed\n");
    return 0;
}
