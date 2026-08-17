# Seeded vulnerable C target for the KavachX ASan / libFuzzer path.
#
# Requires clang (preferred) or gcc. Does not build with MSVC — use WSL2 or Linux on Windows.

CC ?= clang
CFLAGS_COMMON := -std=c11 -Wall -Wextra -g -Isrc
ASAN := -fsanitize=address,undefined -fno-omit-frame-pointer

.PHONY: all build asan fuzz test clean

all: build

build: ## Plain build
	$(CC) $(CFLAGS_COMMON) -O1 -o hdrparse src/main.c src/hdr.c

asan: ## AddressSanitizer + UndefinedBehaviorSanitizer build
	$(CC) $(CFLAGS_COMMON) -O1 $(ASAN) -o hdrparse-asan src/main.c src/hdr.c

fuzz: ## libFuzzer harness (clang only)
	$(CC) $(CFLAGS_COMMON) -O1 -fsanitize=fuzzer,address,undefined -o fuzz_hdr src/fuzz_hdr.c src/hdr.c

test: ## Build and run the target's own tests under ASan
	$(CC) $(CFLAGS_COMMON) -O1 $(ASAN) -o test_hdr tests/test_hdr.c src/hdr.c
	./test_hdr

clean:
	rm -f hdrparse hdrparse-asan fuzz_hdr test_hdr
	rm -rf *.dSYM crash-* leak-* timeout-*
