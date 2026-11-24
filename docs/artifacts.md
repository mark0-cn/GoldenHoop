# Artifact storage

The `goldenhoop-artifacts` crate implements bounded immutable blobs on `object_store` local filesystem and S3-compatible backends. This is the storage layer: public artifact routes, durable artifact tasks and sandbox file capture are the next integration increment. Profiles do not advertise Artifacts yet.

Every object key is generated from a non-nil installation UUID and blob UUID. Callers cannot supply a filesystem path or arbitrary object key. A blob reference contains its ID, byte count and lowercase SHA-256. The initial transfer limit is 16 MiB; large snapshot streaming is a separate M4 requirement.

Writes use create-if-absent and verify the stored bytes before returning. Repeating an ID with identical content succeeds; a different payload cannot overwrite it. Reads check the backend size, bound the incoming stream, and verify its actual length and digest. Deletion requires a fresh HEAD returning NotFound; an acknowledgement followed by a permission/transport error is unconfirmed cleanup.

An ambiguous backend error must be reconciled using the same blob ID. The storage layer cannot atomically commit control-database state and remote objects; that responsibility belongs to the durable worker integration. The actual backend probe writes, reads, deletes and checks absence, with cleanup after both successful and failed operations. Failed probe cleanup preserves the affected blob UUID in its error.

Local roots are private host directories and must never be mounted in workloads. Existing Unix roots with group/other permissions or a final symlink are refused. The root and its parent hierarchy must be administrator-controlled: `object_store` local storage follows symlinks and is not an isolation boundary for untrusted host filesystem writers. Only generated keys are used within it. File/directory synchronization is enabled; directory fsync is unavailable on Windows. Empty object directories are collected during deletion. See the library's [filesystem contract](https://docs.rs/object_store/0.14.2/object_store/local/struct.LocalFileSystem.html).

S3 configuration requires an explicit bucket, region, endpoint and static credentials, with an optional session token. It does not load ambient AWS credentials or silently fall back locally. HTTPS is required except for HTTP loopback test endpoints. The dedicated HTTP connector rejects redirects and environment proxies. Each backend operation has a 30-second outer deadline. Compound write/verify/probe operations can take multiple bounded operations.

## Evidence

Local filesystem contracts cover reopen, concurrent writes, tamper detection, installation prefix separation, size/ID limits, empty content and confirmed repeated deletion. Unix CI also verifies private permissions and root symlink refusal. Separate HTTP fault injection proves redirect refusal and that a failed absence check is not deletion success; these tests do not prove S3 compatibility.

The actual [S3-compatible fixture record](evidence/m2-artifact-s3-windows-docker.json) verifies nine cases against RustFS 1.0.6 at the recorded immutable image digest. It checks the bucket is empty, deletes that test bucket, removes its labeled container and verifies removal of the downloaded fixture image. It uses tmpfs data, no host bind mounts, fresh credentials and a loopback-only port. It does not establish compatibility with AWS S3 or every S3-compatible provider.

```text
cargo build -p goldenhoop-artifacts --example s3_contract
docker pull rustfs/rustfs@sha256:ee717072290bec9b11abfc0365f8310b00df1cd9b3639943edae47bdef05044a
python -B tests/artifact_contract.py --binary target/debug/examples/s3_contract --output evidence/artifacts.json --remove-image
```

Use `--remove-image` only when the fixture image was pulled for this task. It refuses to remove an image used by another container. The fixture does not use global container, image or volume pruning.

## Pending control integration

- Reserve artifact identity, metadata and idempotency in SQLite before a worker writes a blob. Long operations return an operation ID.
- Capture only an authorized workspace file through the agent. Provider credentials and local storage paths stay outside the workload and public responses.
- Persist requested/uploading/available/failed/deleting/deleted states. Recover an interrupted upload by verifying its existing blob; never publish changed source bytes under an already prepared digest.
- Preserve concurrent deletion intent. Charge quotas until cleanup is confirmed. Artifact retention is independent of sandbox expiration; remove retained user artifacts only through explicit deletion.
