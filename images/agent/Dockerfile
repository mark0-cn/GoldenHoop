FROM rust:1-bookworm AS build
WORKDIR /src
RUN rustup component add clippy rustfmt
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=goldenhoop-rust-target,target=/src/target \
    cargo fmt --all --check \
    && cargo clippy --locked --workspace --all-targets -- -D warnings \
    && cargo test --locked --workspace \
    && cargo build --locked --release -p goldenhoop-agent \
    && cp /src/target/release/goldenhoop-agent /goldenhoop-agent

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 workload && useradd --uid 1000 --gid 1000 --no-create-home workload \
    && mkdir -p /workspace /run/goldenhoop \
    && chown 1000:1000 /workspace && chmod 2770 /workspace
COPY --from=build /goldenhoop-agent /usr/local/bin/goldenhoop-agent
ENV GOLDENHOOP_ISOLATED_AGENT=1
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/goldenhoop-agent", "serve"]
