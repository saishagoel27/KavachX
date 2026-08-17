# vulnerable-c-demo — `hdrparse`

> ⚠️ **Intentionally vulnerable.** A deterministic AddressSanitizer / libFuzzer target for the
> KavachX proof of concept. Do not build this into anything real.

A header-block parser with one seeded memory-safety bug.

## Seeded weakness

`src/hdr.c`, `slot_write()` — **CWE-787, out-of-bounds write**:

```c
/* value_len comes straight from the input and is never clamped to SLOT_VALUE_CAP */
memcpy(slot->value, value, value_len);
slot->value[value_len] = '\0';
```

Any header line whose value exceeds `HDR_MAX_VALUE` (64) writes past `slot->value`. Under ASan that
is an immediate `heap-buffer-overflow` — the deterministic signal KavachX validates against.

## Build

```bash
./build.sh          # plain + sanitizer builds, then the target's own tests
make asan           # sanitizer build only
make fuzz           # libFuzzer harness (clang only)
make test           # tests under ASan
```

Needs **clang** (preferred, for libFuzzer) or **gcc**. It does not build with MSVC, so on Windows use
WSL2 or Linux. `examples/vulnerable-demo` is the cross-platform default and exercises the entire
pipeline without a compiler.

## Reproduce the overflow by hand

```bash
make asan
python3 -c "print('x:' + 'A' * 200)" | ./hdrparse-asan
# ==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
```

## Fuzz it

```bash
make fuzz
./fuzz_hdr corpus/ -max_total_time=60
```

`corpus/` holds three benign seeds. libFuzzer reaches the overflow in well under a second.

## What KavachX does with it

When a C toolchain is present, the fuzzing channel uses libFuzzer/AFL++ and the runtime channel uses
the ASan/UBSan build. When one is **not** present, both channels report that they could not run —
`REMAINING.md` records it as a coverage gap rather than a clean result.
