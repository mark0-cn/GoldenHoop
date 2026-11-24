# Engineering requirements

- Preserve the full M0-M6 objective in docs/roadmap.md. Implement and commit verified increments.
- Keep production code in Rust, except the Python SDK and workload dependencies.
- Never advertise an unavailable or unimplemented capability. Never fall back to a weaker runtime.
- A process launch or stream EOF is not execution success. A failed operation is not completed cleanup.
- Do not place host secrets, daemon sockets, or API credentials inside a workload.
- Use actual runtime observations for recovery and cleanup evidence.
- Scope Docker resources with GoldenHoop ownership labels. Never delete unrelated resources.
- Run cargo fmt --all --check, cargo clippy --workspace --all-targets -- -D warnings, and cargo test --workspace for Rust changes.
- Real-backend tests are separate release gates. Skipped hardware tests must remain unverified.
- Update docs/progress.md with concrete implementation and validation evidence before a milestone commit.
