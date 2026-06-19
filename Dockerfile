# syntax=docker/dockerfile:1

# Multi-arch image. The builder runs on the native build platform and, when the
# build host arch differs from the target, cross-compiles to it (no QEMU of the
# Rust build), then the binary ships in a minimal distroless runtime. Pinned to
# the project MSRV so rebuilding a release tag stays reproducible.
FROM --platform=$BUILDPLATFORM rust:1.88-bookworm AS builder
ARG TARGETARCH
WORKDIR /src

# Pick the Rust target for the requested arch. When cross-compiling (build host
# arch != target) install the cross toolchain — the compiler/linker plus the
# target libc headers that cc-rs build scripts such as ring need — and record
# the env that selects it. A native build keeps the default host compiler.
RUN set -eux; \
    host="$(dpkg --print-architecture)"; \
    : > /cross.env; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu; cc=x86_64-linux-gnu-gcc; \
             pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross"; \
             linker_var=CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER; \
             cc_var=CC_x86_64_unknown_linux_gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu; cc=aarch64-linux-gnu-gcc; \
             pkgs="gcc-aarch64-linux-gnu libc6-dev-arm64-cross"; \
             linker_var=CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER; \
             cc_var=CC_aarch64_unknown_linux_gnu ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "$target" > /target; \
    rustup target add "$target"; \
    if [ "$host" != "$TARGETARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends $pkgs; \
      rm -rf /var/lib/apt/lists/*; \
      printf 'export %s=%s\nexport %s=%s\n' "$linker_var" "$cc" "$cc_var" "$cc" > /cross.env; \
    fi

COPY . .
# No BuildKit cargo cache mount: the amd64 and arm64 stages build in parallel,
# and a shared `type=cache` registry mount corrupts under their concurrent crate
# unpacking (".cargo-ok" race -> "failed to unpack"). These images are built
# infrequently (release tags), so a clean compile is the right trade-off.
RUN set -eux; \
    . /cross.env; \
    target="$(cat /target)"; \
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
