# Artifact storage

Artifacts copy an authorized workspace file into private local or S3-compatible storage through the worker. They survive source sandbox expiry/deletion and require explicit deletion; closing a sandbox lease does not delete them. SQLite persists identities, immutable prepared metadata, operations and deletion intent. Available file-capable runtime profiles advertise Artifacts only after an actual storage write/read/list/delete probe. Interactive sessions remain separate M2 work.

Every object key is generated from a non-nil installation UUID and blob UUID. Callers cannot supply a filesystem path or arbitrary object key. A blob reference contains its ID, byte count and lowercase SHA-256. The initial transfer limit is 16 MiB; large snapshot streaming is a separate M4 requirement.

Writes use create-if-absent and verify the stored bytes before returning. Repeating an ID with identical content succeeds; a different payload cannot overwrite it. Reads check the backend size, bound the incoming stream, and verify its actual length and digest. Deletion requires a fresh HEAD returning NotFound; an acknowledgement followed by a permission/transport error is unconfirmed cleanup.

An ambiguous backend error is reconciled using the same blob ID. The worker prepares immutable length/digest before PUT, then commits availability and operation completion atomically. After a crash it first verifies the prepared blob. If absent, it reads the source again only while running and unexpired; changed source bytes fail with Conflict and are collected. A paused source waits. Failed probe cleanup preserves the affected blob UUID in its error.

Local roots are private host directories and must never be mounted in workloads. Existing Unix roots with group/other permissions or a final symlink are refused. The root and its parent hierarchy must be administrator-controlled: `object_store` local storage follows symlinks and is not an isolation boundary for untrusted host filesystem writers. Only generated keys are used within it. File/directory synchronization is enabled; directory fsync is unavailable on Windows. Empty object directories are collected during deletion. See the library's [filesystem contract](https://docs.rs/object_store/0.14.2/object_store/local/struct.LocalFileSystem.html).

S3 configuration requires an explicit bucket, region, endpoint and static credentials, with an optional session token. It does not load ambient AWS credentials or silently fall back locally. HTTPS is required except for HTTP loopback test endpoints. The dedicated HTTP connector rejects redirects and environment proxies. Each backend operation has a 30-second outer deadline. Compound write/verify/probe operations can take multiple bounded operations.

## Configuration

The worker defaults to a private `artifacts` directory beside its database. Override it with `--artifact-root` or GOLDENHOOP_ARTIFACT_ROOT. For S3 use `--artifact-backend s3 --artifact-endpoint https://provider.example --artifact-bucket BUCKET --artifact-region REGION`. Equivalent environment variables are GOLDENHOOP_ARTIFACT_BACKEND, GOLDENHOOP_ARTIFACT_ENDPOINT, GOLDENHOOP_ARTIFACT_BUCKET and GOLDENHOOP_ARTIFACT_REGION. The region defaults to us-east-1; bucket creation is an administrator responsibility.

Supply GOLDENHOOP_ARTIFACT_ACCESS_KEY and GOLDENHOOP_ARTIFACT_SECRET_KEY through the worker environment, with optional GOLDENHOOP_ARTIFACT_SESSION_TOKEN. Credentials, host storage paths and arbitrary backend keys are never supplied to workloads or public responses. Conflicting local/S3 options are refused. The database binds to a storage namespace fingerprint excluding credentials. Credential rotation is allowed; switching roots, endpoints, buckets or regions requires an explicit migration, which is not implemented yet.

## Public contract and clients

| Method | Path | Result |
| --- | --- | --- |
| POST | /v1/sandboxes/{id}/artifacts | 202, artifact and capture operation |
| GET | /v1/artifacts?sandbox_id=UUID&after=UUID&limit=100 | UUID-ordered metadata page; optional source filter |
| GET | /v1/artifacts/{id} | Durable metadata and cleanup observation |
| GET | /v1/artifacts/{id}/content | Verified binary content, application/octet-stream, no-store |
| DELETE | /v1/artifacts/{id} | 202, deletion operation |

Capture takes `{"path":"result.bin","name":"result.bin"}`. The path uses the agent's authorized workspace filesystem operations. The display name is 1-255 UTF-8 bytes and cannot contain controls, path separators, `.` or `..`. Names never become backend keys. Both mutations require Idempotency-Key. Capture replay returns the original identity even after the source expires; different request content conflicts. The API, worker and clients check actual content length and SHA-256 before returning bytes.

Rust and Python sync/async clients provide create_artifact, artifact, list_artifacts, capture_artifact, artifact_bytes and delete_artifact. Capture convenience methods wait for availability and preserve the artifact ID on observation failure; uncertain acceptance preserves the idempotency key. Python async cancellation adds that recovery identity to the exception. Observation cancellation does not delete a retained artifact.

```text
goldenhoop artifact-capture <sandbox-uuid> result.bin --name result.bin
goldenhoop artifact-get <artifact-uuid>
goldenhoop artifact-list --sandbox <sandbox-uuid>
goldenhoop artifact-download <artifact-uuid> downloaded.bin
goldenhoop artifact-delete <artifact-uuid>
```

The capture/delete CLI prints recovery IDs before waiting. Downloads are atomic and refuse an existing destination. Successful deletion verifies the final cleanup observation.

## Durable recovery and cleanup

The metadata layer implements pending/uploading/available/failed/deleting/deleted states, idempotent operations, immutable length/digest, atomic publication/deletion and cleanup-dependent quota release. Transactional schema upgrades preserve installation, sandbox, artifact and operation identities; session metadata uses schema 3. The initial installation limit is 256 retained or uncollected artifacts. Pending captures, retained output and unconfirmed cleanup consume quota.

Deletion intent wins over late upload results and immediately refuses new content requests. Metadata and deletion intent remain accessible while the worker is down; content requires a live worker. A failed capture operation can finish before cleanup; inspect the separate cleanup field.

Cleanup records the last actual observation. A remote PUT may finish after a crash or an earlier absence check. Every five seconds the worker scans its own bounded namespace and collects blobs belonging to failed/deleted metadata. Actual residue reopens cleanup as Unknown and charges quota; it never republishes the deleted business resource. Confirmed absence restores Complete. Available artifacts and IDs with no matching metadata are untouched. Startup probes have a separate temporary prefix that the single active controller also sweeps after its probe finishes. This is eventual reconciliation while the worker/backend are available, not a promise that remote data cannot reappear between observations.

## Actual validation

Local filesystem contracts cover reopen, concurrent writes, tamper detection, installation prefix separation, size/ID limits, empty content and confirmed repeated deletion. Unix CI also verifies private permissions and root symlink refusal. Separate HTTP fault injection proves redirect refusal and that a failed absence check is not deletion success; these tests do not prove S3 compatibility.

The actual [S3-compatible fixture record](evidence/m2-artifact-s3-windows-docker.json) verifies nine cases against RustFS 1.0.6 at the recorded immutable image digest. It checks the bucket is empty, deletes that test bucket, removes its labeled container and verifies removal of the downloaded fixture image. It uses tmpfs data, no host bind mounts, fresh credentials and a loopback-only port. It does not establish compatibility with AWS S3 or every S3-compatible provider.

```text
cargo build -p goldenhoop-artifacts --example s3_contract
docker pull rustfs/rustfs@sha256:ee717072290bec9b11abfc0365f8310b00df1cd9b3639943edae47bdef05044a
python -B tests/artifact_contract.py --binary target/debug/examples/s3_contract --output evidence/artifacts.json --remove-image
```

Use `--remove-image` only when the fixture image was pulled for this task. It refuses to remove an image used by another container. The fixture does not use global container, image or volume pruning.

The [local API/client record](evidence/m2-artifact-api-runc-windows-docker.json) passes 12 cases and all four clients. The [S3-compatible API/client record](evidence/m2-artifact-api-s3-runc-windows-docker.json) passes 15 cases against pinned RustFS 1.0.6. These include source expiry, API/worker restarts, binary digest checks, deletion while the worker is down, an actually paused backend and killed worker, changed-source refusal, verified prepared-blob recovery and late-write collection without republishing. Committed-blob and late-write states are explicit fixture fault injections, not claims about naturally occurring provider races. All test buckets, containers, volumes, processes and temporary directories were removed, as was the fixture image pulled for the S3 run.

```text
cargo build -p goldenhoop-control -p goldenhoop-cli
cargo build -p goldenhoop-client --example sdk_contract
python -B tests/api_contract.py --binary target/debug/goldenhoopd --rust-client target/debug/examples/sdk_contract --cli target/debug/goldenhoop --artifact-backend s3 --remove-artifact-fixture-image --runtime runc --work-dir .test-work --output evidence/api-s3.json
```

Build the trusted agent image as goldenhoop-agent:test and pull the pinned fixture above first. Use the image-removal flag only for an image pulled for this task. AWS S3 itself and other S3-compatible providers remain unverified.
