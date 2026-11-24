FROM rust:1-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy rustfmt \
    && rustup target add x86_64-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=goldenhoop-rust-target,target=/src/target \
    cargo fmt --all --check \
    && cargo clippy --locked --workspace --all-targets -- -D warnings \
    && cargo test --locked --workspace \
    && cargo build --locked --release --target x86_64-unknown-linux-musl -p goldenhoop-jupyter --example kernel_peer \
    && cp /src/target/x86_64-unknown-linux-musl/release/examples/kernel_peer /kernel-peer

FROM goldenhoop-agent:test
LABEL dev.goldenhoop.fixture="kernel-interop"
RUN apt-get update && apt-get install -y --no-install-recommends python3-ipykernel \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /kernel-peer /usr/local/bin/goldenhoop-kernel-peer
ENTRYPOINT ["/usr/local/bin/goldenhoop-kernel-peer"]
