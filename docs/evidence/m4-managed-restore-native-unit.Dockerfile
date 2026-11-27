FROM rust:1-bookworm
ENV CARGO_BUILD_JOBS=2
WORKDIR /src
RUN rustup component add clippy rustfmt
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=goldenhoop-rust-target,target=/src/target \
    find crates -type f -exec touch {} + \
    && cargo fmt --all --check \
    && cargo clippy --locked -p goldenhoop-firecracker --all-targets -- -D warnings \
    && cargo test --locked -p goldenhoop-firecracker --lib lifecycle::restore::tests:: -- --test-threads=1 \
    && cargo test --locked -p goldenhoop-firecracker --lib checkpoint::storage::tests::real_native_collection -- --test-threads=1
