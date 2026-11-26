# Host large artifact storage

`goldenhoop-artifacts` supports private large objects for image and snapshot
integration. It does not publish a snapshot capability or change the existing
16-MiB public file/artifact transfer limit.

`BlobStore::large_reference` allocates no storage. Its `LargeBlobRef` binds the
installation, storage namespace digest, object UUID, upload generation, expected
whole-file SHA256 and length. The controller must durably journal this full
reference before calling `put_large`. A retry uses the same reference; a new
allocation uses a new generation. Never accept a workload-supplied reference as
authorization to access or collect host storage.

Uploads use 4-MiB chunks and a 16-GiB maximum. The store first persists an
immutable intent, then conditionally creates and reads back each chunk. The
final manifest is published only after exact input length and whole-file digest
verification. Each chunk and the manifest are immutable. A conflicting existing
object is refused, not replaced. Failed or cancelled uploads remain unpublished;
their journaled generation can resume with the original bytes or be collected
after its owner fences every writer. Transfers have a bounded total deadline.

`download_large` verifies the manifest identity, chunk shapes, every chunk digest
and final whole-file digest. Its output must be private staging. On failure or
cancellation it may contain partial bytes, so the controller must collect that
staging and expose it only after successful verification and the caller's
required durable filesystem sync. Flushing an `AsyncWrite` is not an fsync claim.

`collect_large` is controller maintenance after all readers/writers for that
generation are fenced. Retain the controller journal until collection succeeds.
Collection verifies the intent and canonical key set before deleting anything,
removes publication first, confirms every key absent by HEAD and finally lists
the exact generation prefix to confirm it empty. Unknown keys or mismatched
intent are retained as evidence. Other generations, small artifacts and foreign
installations/backends are outside that operation's scope. An absent intent with
remaining objects is refused. No bucket-wide collector or multipart upload
session is used. Uncertain storage outcomes explicitly disable automatic replay.

The implementation uses the pinned `object_store` 0.14.2 conditional-create
interface. Its multipart documentation explains that S3/GCS cannot clean up an
abandoned multipart session merely by dropping the uploader; this design uses
bounded ordinary objects whose exact keys are recoverable from the journaled
reference. The dependency version and registry checksum are retained in
`Cargo.lock`. The local dependency source also shows S3's bulk-delete POST, which
the controlled delete-acknowledgement fault test exercises before requiring a
fresh HEAD observation.

Pinned E2B [OCI conversion](https://github.com/e2b-dev/infra/blob/86cb50338fe3bd73c10b13270aaa576b48f5d582/packages/orchestrator/pkg/template/build/core/oci/oci.go)
and [ext4 construction](https://github.com/e2b-dev/infra/blob/86cb50338fe3bd73c10b13270aaa576b48f5d582/packages/orchestrator/pkg/template/build/core/filesystem/ext4.go)
provide useful image-size, conversion and filesystem-integrity boundaries.
GoldenHoop still needs its own production Rust image preparation and actual
snapshot/restore identity gates; the storage component alone does not satisfy
those requirements.
