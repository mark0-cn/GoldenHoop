# Clients and command line

Clients use the GoldenHoop REST API; they do not need access to Docker. Configure a loopback HTTP endpoint or an HTTPS endpoint behind the deployment's TLS proxy. Embedded URL credentials, remote plaintext HTTP, redirects and implicit environment proxies are refused. Tokens are supplied in the Authorization header.

## Rust

Add `goldenhoop-client` from this workspace. It reexports the protocol models.

```rust,no_run
use goldenhoop_client::{Client, CommandSpec, CreateSandbox};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new("http://127.0.0.1:8080", &std::env::var("GOLDENHOOP_API_TOKEN")?)?;
let mut lease = client.lease(&CreateSandbox::new("local-gvisor", "python:3.12-slim")).await?;
let output = client.run(lease.id(), &CommandSpec::new(["python3", "-c", "print(42)"])).await;
// Await cleanup before propagating a command/observation error.
lease.close().await?;
let output = output?;
assert_eq!(output.stdout, b"42\n");
# Ok(()) }
```

`close().await` confirms termination and cleanup. Rust cannot await in Drop: dropping a lease only schedules a best-effort cleanup when a Tokio runtime is still alive. Keep the runtime alive and explicitly close leases when confirmation is required. Create-wait failures attempt confirmed cleanup and preserve the resource ID if that cleanup fails. The workload image must already be cached on the execution host.

## Python

Install the source package with `python -m pip install ./sdk/python`. Python 3.11+ is required. Responses preserve the server's JSON fields as dictionaries; binary files/output are bytes.

```python
import os
from goldenhoop import Client, Command, CreateSandbox

with Client("http://127.0.0.1:8080", os.environ["GOLDENHOOP_API_TOKEN"]) as client:
    with client.lease(CreateSandbox("local-gvisor", "python:3.12-slim")) as sandbox:
        result = client.run(sandbox.id, Command(["python3", "-c", "print(42)"]))
        assert result.execution["state"] == "succeeded"
        assert result.stdout == b"42\n"
```

Use `async with AsyncClient(...) as client`, `async with client.lease(...)`, and await the methods for native asyncio. Lease context exit waits for confirmed cleanup, including exceptions in caller code and cancellation of an async context owner. A cleanup failure raises `CleanupError` with the sandbox ID and the original caller error. Closing the HTTP client alone does not terminate manually created sandboxes.

For direct streaming use `with contextlib.closing(client.events(id)) as events` or `async with contextlib.aclosing(client.events(id)) as events`. Save the last delivered event's sequence and reconnect with `events(id, after=sequence)`. Close an abandoned observer promptly.

## CLI

Build with `cargo build -p goldenhoop-cli` or install with `cargo install --path crates/cli`. Set `GOLDENHOOP_API_TOKEN` and optionally `GOLDENHOOP_ENDPOINT` in the client environment.

```text
goldenhoop profiles
goldenhoop create --profile local-gvisor --image python:3.12-slim
goldenhoop exec <sandbox-uuid> -- python3 -c "print(42)"
goldenhoop file-put <sandbox-uuid> local.bin remote.bin
goldenhoop file-get <sandbox-uuid> remote.bin downloaded.bin
goldenhoop pause <sandbox-uuid>
goldenhoop resume <sandbox-uuid>
goldenhoop diagnostics <sandbox-uuid>
goldenhoop delete <sandbox-uuid>
```

`exec` takes literal argv after `--`; shell expansion requires explicitly invoking a shell. It writes binary stdout/stderr after collecting a bounded result. `--json` returns the execution and base64 output instead. Command exit codes are preserved in 1-255, with 124 for timeout, 130 for cancellation and 125 for client/observation failures. Check the JSON execution state when exact classification matters. Downloads are atomic and refuse to overwrite an existing local destination.

## Outcomes, retries and observation

`run` returns an explicit terminal execution with confirmed cleanup, including nonzero exit, timeout and cancellation. Callers must inspect its state; receiving a result is not synonymous with successful code execution. A stream EOF is never success. Collectors reconnect to their last complete cursor at most three times and reject gaps, resource mismatches and oversized frames/output.

Waiting, a client deadline, observer disconnect and cancellation of an observation coroutine do not cancel a remote execution. Use the explicit cancel endpoint. An observation error carries the execution ID so it can be inspected or cancelled. A transport failure during create/start may leave an accepted request whose response was lost: convenience methods report `UncertainRequest` with the original idempotency key. Replay the same request with that key; a new key can create duplicate work. Low-level keyed methods accept caller-managed keys and bounded transport retries preserve them.

## Actual validation

The API harness can launch both services, the Rust SDK example, the Python sync/async SDK and the Rust CLI against a fresh installation:

```text
cargo build -p goldenhoop-control -p goldenhoop-cli
cargo build -p goldenhoop-client --example sdk_contract
python -B tests/api_contract.py --binary target/debug/goldenhoopd --rust-client target/debug/examples/sdk_contract --cli target/debug/goldenhoop --runtime runc --work-dir .test-work --output evidence/clients.json
```

Use `runsc` only on a real gVisor host. `--clients-only` isolates client debugging and is not a complete API contract pass. The harness confirms removal of its labeled containers, volumes, service processes and temporary directory on failure as well as success. Protocol regression tests separately exercise premature EOF, partial-frame reconnect, sequence validation and deadline handling; these do not establish a runtime isolation boundary.
