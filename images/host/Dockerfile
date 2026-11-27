FROM rust:1-bookworm AS build
ENV CARGO_BUILD_JOBS=2
WORKDIR /src
RUN rustup component add clippy rustfmt
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ARG VALIDATE_WORKSPACE=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=goldenhoop-rust-target,target=/src/target \
    find crates -type f -exec touch {} + \
    && if [ "$VALIDATE_WORKSPACE" = "1" ]; then \
         cargo fmt --all --check \
         && cargo clippy --locked --workspace --all-targets -- -D warnings \
         && cargo test --locked --workspace -- --test-threads=2; \
       elif [ "$VALIDATE_WORKSPACE" != "0" ]; then exit 64; fi \
    && cargo build --locked --release -p goldenhoop-images \
    && cp target/release/goldenhoop-images /goldenhoop-images

# Trusted host service only. The administrator supplies its local daemon socket
# and private state. No socket or host path is ever given to a source workload.
FROM debian:bookworm-slim
LABEL dev.goldenhoop.image-host="source-export-v1"
COPY --from=build /goldenhoop-images /usr/local/bin/goldenhoop-images
ENTRYPOINT ["/usr/local/bin/goldenhoop-images"]
