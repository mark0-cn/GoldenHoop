FROM rust:1-bookworm AS build
ENV CARGO_BUILD_JOBS=2
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy rustfmt \
    && rustup target add x86_64-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ARG VALIDATE_WORKSPACE=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=goldenhoop-rust-target,target=/src/target \
    # Source contexts can restore mtimes older than shared target artifacts.
    # Refresh all workspace inputs before Cargo decides what can be reused.
    find crates -type f -exec touch {} + \
    && if [ "$VALIDATE_WORKSPACE" = "1" ]; then \
         cargo fmt --all --check \
         && cargo clippy --locked --workspace --all-targets -- -D warnings \
         && cargo test --locked --workspace; \
       elif [ "$VALIDATE_WORKSPACE" != "0" ]; then exit 64; fi \
    && cargo build --locked --release --target x86_64-unknown-linux-musl -p goldenhoop-agent \
    && cargo build --locked --release --target x86_64-unknown-linux-musl -p goldenhoop-egress \
    && cargo build --locked --release --target x86_64-unknown-linux-musl -p goldenhoop-init \
    && cp /src/target/x86_64-unknown-linux-musl/release/goldenhoop-agent /goldenhoop-agent \
    && cp /src/target/x86_64-unknown-linux-musl/release/goldenhoop-egress /goldenhoop-egress \
    && cp /src/target/x86_64-unknown-linux-musl/release/goldenhoop-init /goldenhoop-init

FROM debian:bookworm-slim AS host-egress
LABEL dev.goldenhoop.egress="host-netfilter"
RUN apt-get update && apt-get install -y --no-install-recommends nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /goldenhoop-egress /usr/local/bin/goldenhoop-egress
ENTRYPOINT ["/usr/local/bin/goldenhoop-egress"]

FROM debian:bookworm-slim AS agent-base
LABEL dev.goldenhoop.agent.libc="musl"
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 workload && useradd --uid 1000 --gid 1000 --no-create-home workload \
    && mkdir -p /workspace /run/goldenhoop \
    && chown 1000:1000 /workspace && chmod 2770 /workspace
COPY --from=build /goldenhoop-agent /usr/local/bin/goldenhoop-agent
ENV GOLDENHOOP_ISOLATED_AGENT=1
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/goldenhoop-agent", "serve"]

FROM agent-base AS microvm-rootfs
LABEL dev.goldenhoop.microvm="rootfs"
COPY --from=build /goldenhoop-init /sbin/goldenhoop-init
COPY images/microvm/guest.json /etc/goldenhoop/guest.json
ENTRYPOINT ["/sbin/goldenhoop-init"]

# Keep the default build target compatible with the existing container backend.
FROM agent-base AS agent
