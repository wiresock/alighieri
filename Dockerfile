# syntax=docker/dockerfile:1

# Multi-arch image. The builder always runs on the native build platform and
# cross-compiles to the requested target arch (no QEMU emulation of the Rust
# build), then the binary ships in a minimal distroless runtime.
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder
ARG TARGETARCH
WORKDIR /src

# Map the Docker target arch to a Rust target, installing the cross toolchain
# (linker + C compiler for cc-rs build scripts such as ring) for aarch64.
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu; \
             apt-get update; \
             # gcc-aarch64-linux-gnu is the cross compiler/linker;
             # libc6-dev-arm64-cross provides the target libc headers ring's
             # build needs (a Recommends, so it must be named under
             # --no-install-recommends).
             apt-get install -y --no-install-recommends \
                 gcc-aarch64-linux-gnu libc6-dev-arm64-cross; \
             rm -rf /var/lib/apt/lists/* ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "$target" > /target; \
    rustup target add "$target"

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc

COPY . .
RUN target="$(cat /target)"; \
    cargo build --release --locked --target "$target"; \
    cp "target/$target/release/alighieri" /alighieri

# Distroless runtime (glibc, matches the bookworm builder ABI): no shell or
# package manager, runs as a non-root user. Use the :debug-nonroot tag if you
# need a busybox shell to poke around.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /alighieri /usr/local/bin/alighieri
EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/alighieri"]
# Mount your config here, or override these args. Use logoutput: stdout and
# internal: 0.0.0.0 so logs reach `docker logs` and the listener is reachable.
CMD ["--config", "/etc/alighieri/alighieri.conf"]
