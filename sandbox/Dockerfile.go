# KavachX sandbox image — Go targets.
#
# Selected automatically when the detected project language is go (app/sandbox/images.py). Same
# isolation as every other sandbox image; only the toolchain differs. The Go compiler is present so
# `go build` / `go mod download` run in the writable, networked build phase, and the built binary
# can be executed in the locked-down execute phase.
#
# Build:
#   docker build -f sandbox/Dockerfile.go -t kavachx/sandbox-go:dev sandbox

FROM golang:1.22-bookworm

# The execute phase gives the container no interface; drop the network tools the base image ships.
RUN rm -f /usr/bin/curl /usr/bin/wget /usr/bin/nc /usr/bin/telnet 2>/dev/null || true

# The module cache and build cache live under HOME, which the adapter redirects to the writable
# tmpfs. Pin the toolchain to the image's own version so a go.mod directive cannot trigger a
# network toolchain download in the no-network execute phase.
ENV GOFLAGS=-mod=mod \
    GOTOOLCHAIN=local \
    GOPATH=/workspace/.tmp/go \
    GOCACHE=/workspace/.tmp/go-build

WORKDIR /workspace

# nobody in the execute phase; the adapter overrides to the host uid for the writable build phase.
USER 65534:65534

CMD ["go", "version"]
