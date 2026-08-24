# KavachX sandbox image — the execution environment for hostile code.
#
# This image is what the gVisor and Firecracker adapters execute. It deliberately contains almost
# nothing: a Python runtime, the sanitizer-capable toolchain for native targets, and no network
# tools at all. There is no curl, no wget, no git, no ssh, and no package manager left behind —
# not because their absence is a security boundary on its own (the boundary is gVisor/Firecracker
# plus `--network none`), but because a smaller image is a smaller thing to reason about.
#
# Build:
#   docker build -t kavachx/sandbox:dev ./sandbox
#
# It is never run directly. The adapter supplies every flag that matters:
#   --runtime=runsc --network none --read-only --user 65534:65534 --cap-drop ALL
#   --security-opt no-new-privileges --pids-limit --memory --cpus --tmpfs

FROM python:3.12-slim

# Native targets need a sanitizer-capable compiler; libFuzzer ships with clang.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clang \
      llvm \
      libclang-rt-dev \
      make \
      binutils \
      time \
 && rm -rf /var/lib/apt/lists/* \
 # Remove the network tools the base image ships with. The adapter gives the container no
 # interface at all, so these are unreachable anyway — deleting them removes the question.
 && rm -f /usr/bin/curl /usr/bin/wget /usr/bin/nc /usr/bin/telnet 2>/dev/null || true

# Deterministic interpreter behaviour, so two runs of the same input are byte-comparable.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PYTHONIOENCODING=utf-8 \
    ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:symbolize=1:print_stacktrace=1 \
    UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

# The workspace is bind-mounted read-only by the adapter; only the tmpfs is writable.
WORKDIR /workspace

# nobody. The adapter passes --user 65534:65534 as well; this is the fallback if it does not.
USER 65534:65534

# No ENTRYPOINT: every execution is an explicit argument vector from the adapter, never a shell
# string, so nothing here can interpret a metacharacter.
CMD ["python", "-c", "print('kavachx sandbox image; the adapter supplies the command')"]
