# vulnerable-demo — `reportsvc`

> ⚠️ **This code is intentionally vulnerable.** It exists only as a deterministic analysis
> target for the KavachX proof of concept. Do not install it, deploy it, or copy any of it
> into real software.

A tiny local report service with a single JSON entrypoint. No network, no dependencies
beyond the Python standard library, no external services — so a KavachX run is fully
reproducible offline.

## Interface

```bash
python src/main.py --request '{"op":"ping"}'
python src/main.py --request '{"op":"parse","headers":"x-trace-id:9f2a\n"}'
python src/main.py --request '{"op":"export","name":"q3-summary","format":"csv"}'
python src/main.py --request '{"op":"asset","path":"report.tmpl"}'
```

Operations: `ping`, `status`, `parse`, `export`, `asset`.

Exit codes: `0` handled, `1` unhandled exception inside the service, `2` bad CLI input.

## Seeded weaknesses

| Where | Class | Trigger |
| --- | --- | --- |
| `exporter.export_report` | OS command injection (CWE-78) | `name` is interpolated into a string passed to `subprocess.run(..., shell=True)` |
| `parser.parse_header` | Unchecked length boundary (CWE-1284) | more than `MAX_HEADER_SLOTS` header lines writes past the slot table |
| `assets.read_asset` | Path traversal (CWE-22) | `ASSET_ROOT / relative_path` is never confined to `ASSET_ROOT` |
| `config.DEFAULT_CONFIG` | Debug left enabled (CWE-489) | `debug: true` and `bind_host: 0.0.0.0` shipped as defaults |

Each one is marked in-source with a `SEEDED VULNERABILITY` comment naming the CWE, so
nothing here is a surprise to a reader — the point is that KavachX has to *prove* them by
execution, not by reading the comment.

## Benign corpus

`corpus/benign/*.json` — twelve requests that represent normal operation. KavachX uses them
twice: to observe value profiles while synthesising SAMHITA clauses, and as the reference
behaviour for the differential-replay stage of the Refutation Gauntlet.

## Build / test

```bash
./build.sh          # byte-compile and run the target's own test suite
make test           # same via make
python -m pytest tests -q
```

There is nothing to compile — `build.sh` exists so KavachX exercises the same
build → observe → validate path it would use on a native target.

## The C variant

`examples/vulnerable-c-demo` carries a heap-overflow target for the ASan / libFuzzer
discovery path. It needs `clang` or `gcc` and therefore only builds on Linux, macOS or WSL;
this Python target is the cross-platform default.
