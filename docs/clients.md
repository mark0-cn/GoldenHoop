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
goldenhoop artifact-capture <sandbox-uuid> result.bin --name result.bin
goldenhoop artifact-download <artifact-uuid> downloaded.bin
goldenhoop artifact-delete <artifact-uuid>
goldenhoop delete <sandbox-uuid>
```

`exec` takes literal argv after `--`; shell expansion requires explicitly invoking a shell. It writes binary stdout/stderr after collecting a bounded result. `--json` returns the execution and base64 output instead. Command exit codes are preserved in 1-255, with 124 for timeout, 130 for cancellation and 125 for client/observation failures. Check the JSON execution state when exact classification matters. Downloads are atomic and refuse to overwrite an existing local destination.

## Outcomes, retries and observation

`run` returns an explicit terminal execution with confirmed cleanup, including nonzero exit, timeout and cancellation. Callers must inspect its state; receiving a result is not synonymous with successful code execution. A stream EOF is never success. Collectors reconnect to their last complete cursor at most three times and reject gaps, resource mismatches and oversized frames/output.

Waiting, a client deadline, observer disconnect and cancellation of an observation coroutine do not cancel a remote execution. Use the explicit cancel endpoint. An observation error carries the execution ID so it can be inspected or cancelled. A transport failure during create/start may leave an accepted request whose response was lost: convenience methods report `UncertainRequest` with the original idempotency key. Replay the same request with that key; a new key can create duplicate work. Low-level keyed methods accept caller-managed keys and bounded transport retries preserve them.

## Retained artifacts

Rust and Python sync/async clients expose create_artifact, artifact, list_artifacts, capture_artifact, artifact_bytes and delete_artifact. CreateArtifact takes a workspace path and optional display name. Capture waits for availability; downloads verify size and SHA-256 and return bytes. A retained artifact survives closing its source sandbox lease and requires explicit deletion. Wait for the delete operation and verify state=deleted with cleanup=complete.

Capture observation failures preserve the artifact ID (`Error::Artifact` in Rust and ArtifactError in Python). Uncertain acceptance preserves the idempotency key; Python async cancellation records the available recovery ID/key in the exception notes. Cancelling observation does not delete retained output. Metadata remains readable while the worker is down, but content requests fail explicitly. CLI capture/delete prints recovery IDs before waiting, and downloads refuse to overwrite local files. See [artifact routes, limits and recovery](artifacts.md).

## Interactive Rust sessions

Rust Client now provides create_session, session, list_sessions, session_control, session_control_status, wait_session_control and session_socket. SessionSpec::shell starts /bin/sh with pipes; setting terminal requests an actual PTY. Keep the source sandbox lease alive while using the session. Use the ordinary execution cancel/events methods with its execution ID, and explicitly close the source lease to confirm sandbox cleanup.

Controls carry caller-managed contiguous sequences. Save them before submitting. Applied confirms delivery, while Rejected and Unknown remain distinct final receipts. The WebSocket channel validates event IDs/order and explicit completion, exposes its last cursor, and reconnects with that cursor without restarting the process. Socket close/drop does not cancel remote execution. The actual Rust SDK contract covers REST stdin and terminal reconnect/input replay/resize. Python/CLI also support sessions over REST/SSE; see [the public session protocol](sessions.md).

Python exports SessionSpec and SessionControl.write/close_input/resize. Both clients provide create_session, session, list_sessions, session_control, session_control_status and wait_session_control; existing events/cancel/wait_execution methods accept the same execution ID. SessionControlError preserves the ID/sequence on observation failure. Async cancellation notes identify a possibly accepted input and leave the remote process running. Use an explicitly closed SSE observer when streaming a live session.

The CLI supports session-create/get/list/write/close-input/resize/receipt/events. session-create accepts --pty, --rows, --columns, --timeout, --cwd and literal argv after --. session-write takes a caller-managed sequence and a bounded binary file or stdin. Input commands wait for delivery and return 125 for rejected/unknown delivery; they do not report a shell statement's exit code. session-events emits JSON lines, supports --after and refuses EOF without completion. Use cancel with the session execution ID and close the source lease/sandbox to confirm full cleanup.

## Python code contexts

The worker must have an explicitly successful kernel-image probe. Use a cached workload image containing Python and ipykernel, and keep the source sandbox lease alive. Contexts share its filesystem and resource limits.

```python
from uuid import uuid4
from goldenhoop import Client, CreateSandbox, CodeContextSpec, CodeRunSpec

with Client(endpoint, token) as client:
    request = CreateSandbox("local-gvisor", "my-python-kernel:local",
                            required_capabilities=["code_contexts"])
    with client.lease(request) as sandbox:
        context = client.create_code_context(sandbox.id, CodeContextSpec(), str(uuid4()))
        client.wait_code_context_ready(context["id"])
        client.run_code(context["id"], CodeRunSpec("value = 40"))
        output = client.run_code(context["id"], CodeRunSpec("print(value + 2)\nvalue + 2"))
        assert output.run["state"] == "kernel_succeeded"
        print(output.stdout, output.results)
        client.close_code_context(context["id"], str(uuid4()))
        client.wait_code_context_closed(context["id"])
```

AsyncClient exposes the same methods with await, and code_context_events is an async iterator. Rust Client provides create_code_context, code_context, list_code_contexts, close_code_context, wait_code_context_ready/closed, start_code, code_run, list_code_runs, cancel_code_run, run_code and run_code_with_key. Python uses an optional explicit `key` on run_code. CodeRunOutput contains the run record, text stdout/stderr, MIME result/display content and kernel errors.

KernelSucceeded/KernelFailed are interpreter observations. A successful code result leaves the context alive; an exception can also leave it usable. Unknown becomes `Error::CodeObservation(run_id, ...)` in Rust or CodeObservationError with run_id in Python. Inspect that ID rather than submitting new work under a different key. Interrupted acceptance retains the original key, and async Python cancellation notes preserve a known run ID or possibly accepted key. Neither observation cancellation nor SSE drop cancels the interpreter.

A run retains `events_after`, the context's public cursor when accepted. Reusing a create key retains that cursor so a collector can recover the previous result. Context events use `code_context_events(context_id, after)` and include optional originating run IDs and late/background provenance. Context streams end only with confirmed closure (or an already collected context snapshot); run collectors return on a matching completion. Rich frames, output and receive buffers are bounded. Binary-buffer protocol extensions are refused; use workspace files and retained artifacts for larger outputs.

Cancelling a run closes its whole context, cancels its queued code and discards interpreter state. cancel_code_run records intent; wait_code_context_closed confirms collection. An SDK wait deadline does not cancel work. Source pause defers context RPC; host TTL still expires and collects the source. [Public routes, quotas and recovery](code-contexts.md).

The CLI adds context-create/get/list/close/events and code-run/get/list/cancel:

```text
goldenhoop context-create <sandbox-uuid>
goldenhoop code-run <context-uuid> snippet.py --idempotency-key <saved-key>
goldenhoop code-run <context-uuid> snippet.py --no-wait
goldenhoop code-get <run-uuid>
goldenhoop code-cancel <run-uuid>
goldenhoop context-close <context-uuid>
goldenhoop context-events <context-uuid> --after <saved-sequence>
```

code-run reads at most 64 KiB of literal UTF-8 source, using `-` for stdin, and emits structured JSON. It returns 0 for kernel success, 1 for a kernel exception, 124 for timeout, 130 for cancellation and 125 for rejected/uncertain/client observations. `--no-wait` only confirms acceptance. Context creation/closure wait for readiness/collection, and recovery IDs/keys are printed before waiting. Context events emit resumable JSON lines; EOF alone is insufficient.

## Actual validation

The API harness can launch both services, the Rust SDK example, the Python sync/async SDK and the Rust CLI against a fresh installation:

```text
cargo build -p goldenhoop-control -p goldenhoop-cli
cargo build -p goldenhoop-client --example sdk_contract
python -B tests/api_contract.py --binary target/debug/goldenhoopd --rust-client target/debug/examples/sdk_contract --cli target/debug/goldenhoop --runtime runc --work-dir .test-work --output evidence/clients.json
```

Use `runsc` only on a real gVisor host. `--clients-only` isolates client debugging and is not a complete API contract pass. All four clients capture output, close the source sandbox, verify retained bytes and explicitly delete the artifact. The harness confirms removal of its labeled containers, volumes, service processes and temporary directory on failure as well as success. Protocol regressions separately exercise premature EOF, partial-frame reconnect, sequence validation, deadline handling and artifact digest mismatch; these do not establish a runtime isolation boundary.

Public code contexts and all four client loops pass on actual [gVisor](evidence/ci-45393987529/agent-runsc/api-runsc.json), [runc](evidence/ci-45393987529/agent-runc/api-runc.json) and [S3-compatible storage](evidence/ci-45393987398/api-s3/api-s3.json), with owned resources and temporary files collected.


## Isolated child sandboxes

Reserve an additional child budget when creating the parent. Its own resources stay its workload hard limits; the installation charges the complete envelope once. Child creation uses the parent's profile/image, bounded expiry and a separate workspace. Allocations remain held until collection, including Unknown cleanup. Inspect reservations with sandbox_scope/scope and list direct children with isolated_sessions/isolated-list.

```python
from goldenhoop import Client, CreateSandbox, CreateIsolatedSession, Command

request = CreateSandbox(
    "local-gvisor", "goldenhoop-agent:test",
    child_budget={"cpu_millis": 1000, "memory_bytes": 1073741824, "pids": 256},
)
with Client(endpoint, token) as client:
    with client.lease(request) as parent:
        with client.isolated_lease(parent.id, CreateIsolatedSession(
            feature_limit=["commands", "files"],
        )) as child:
            output = client.run(child.id, Command(["python3", "-c", "print(42)"]))
            assert output.stdout == b"42\n"
```

AsyncClient supports the same operations with await and async with. Rust provides create_isolated_session, isolated_sessions, sandbox_scope and isolated_lease. Both lease types confirm child cleanup, and closing a parent collects any remaining descendants. Explicit create calls accept caller-owned idempotency keys; uncertain acceptance must replay the same parent, key and specification. Cancelling an observer does not cancel its child workload.

CLI create and isolated-create accept --child-cpu-millis, --child-memory-bytes and --child-pids together. --feature-limit commands,files sets an immutable callable-feature ceiling; --no-features sets an empty ceiling. --require lists required verified capabilities. isolated-create accepts an optional image/TTL and --no-wait, while emitting accepted identity before waiting. Use ordinary exec/files/sessions/contexts/delete commands with the child UUID. A feature ceiling controls platform calls; it does not prevent filesystem access by a permitted interpreter or command. Ancestor lifecycle and mandatory isolation enforcement still apply.
