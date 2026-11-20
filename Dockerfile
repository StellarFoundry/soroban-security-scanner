# Multi-stage build: the builder and all of its source files stay out of the
# runtime image. Both base images are pinned by tag and digest.
FROM rust:1.91.1-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock README.md ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY xtask ./xtask

# rustup ships prebuilt musl libc and lld, so no external linker is needed.
ARG TARGETARCH=amd64
RUN case "${TARGETARCH}" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && rustup target add "${target}" \
    && cargo build --release --locked --target "${target}" -p soroban-scan-cli \
    && cp "target/${target}/release/soroban-scan" /usr/local/bin/soroban-scan

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

LABEL org.opencontainers.image.title="soroban-scan" \
      org.opencontainers.image.description="Deterministic security analysis for Stellar Soroban smart contracts and Rust projects." \
      org.opencontainers.image.source="https://github.com/AyinkxLab/soroban-security-scanner" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /usr/local/bin/soroban-scan /usr/local/bin/soroban-scan

# Owned by root and never written to: mount a writable directory for --output.
WORKDIR /workspace
USER 65532:65532

ENTRYPOINT ["soroban-scan"]
CMD ["scan", ".", "--fail-on", "high"]

# The scanner is a one-shot CLI; this checks that the binary starts, not that a
# scan found (or missed) a finding. See docs/docker.md.
HEALTHCHECK --interval=5m --timeout=5s --start-period=10s --retries=3 \
    CMD ["soroban-scan", "version"]
