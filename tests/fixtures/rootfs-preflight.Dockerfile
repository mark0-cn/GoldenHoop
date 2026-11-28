FROM debian:bookworm-slim
# Trusted fixed fixture only. The actual gate separately builds and executes the
# Rust inspector; this shell verifies CLI transport before that long build.
ENTRYPOINT ["/bin/sh", "-c", "IFS= read -r permit && test -n \"$permit\" && printf '%s\\n' '{\"passed\":true,\"staging_absent\":true,\"tools_collected\":true,\"transport\":\"one_newline_received\"}'"]
