//! Real SQLite admission/restart tests. Runtime observations are synthetic;
//! these tests do not establish memory snapshot or cleanup hardware support.
use chrono::Utc;
use goldenhoop_protocol::*;
use goldenhoop_runtime::RuntimeHandle;
use goldenhoop_store::Store;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[path = "snapshot_durability/collection.rs"]
mod collection;
#[path = "snapshot_durability/restoration.rs"]
mod restoration;

fn profile() -> RuntimeProfile {
    RuntimeProfile {
        id: "snapshot-fixture".into(),
        placement: Placement::Local,
        isolation: Isolation::Firecracker,
        availability: Availability::Available,
        capabilities: BTreeSet::from([
            Capability::Commands,
            Capability::Files,
            Capability::Pause,
            Capability::NetworkIsolation,
            Capability::MemorySnapshot,
        ]),
        code_languages: Default::default(),
        max_resources: ResourceLimits {
            cpu_millis: 4000,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            pids: 1024,
        },
        max_ttl_seconds: 3600,
        reason: None,
    }
}
fn capture() -> CreateSnapshot {
    CreateSnapshot {
        kind: SnapshotKind::MemoryAndDisk,
    }
}
async fn source(store: &Store) -> (Sandbox, RuntimeHandle) {
    let request = CreateSandbox::new("snapshot-fixture", "sha256:fixture-image");
    let created = store
        .create_sandbox(&profile(), &request, &Uuid::new_v4().to_string())
        .await
        .unwrap();
    let mut stored = store.sandbox(created.sandbox.id).await.unwrap();
    stored.sandbox.state = SandboxState::Starting;
    store.observe(stored.clone()).await.unwrap();
    let handle = RuntimeHandle {
        sandbox_id: stored.sandbox.id,
        profile: "snapshot-fixture".into(),
        backend_ref: format!("private-runtime-{}", Uuid::new_v4()),
    };
    stored.sandbox.state = SandboxState::Running;
    stored.handle = Some(handle.clone());
    store.observe(stored).await.unwrap();
    (
        store.sandbox(created.sandbox.id).await.unwrap().sandbox,
        handle,
    )
}
async fn running(store: &Store, sandbox: Uuid) -> Execution {
    let mut value = store
        .create_execution(
            sandbox,
            &CommandSpec::new(["sleep", "120"]),
            &Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
    value.state = ExecutionState::Running;
    value.started_at = Some(Utc::now());
    value.cleanup = CleanupState::Pending;
    let event = ExecutionEvent {
        sequence: 1,
        execution_id: value.id,
        timestamp: Utc::now(),
        kind: EventKind::Started,
        data: serde_json::json!({}),
    };
    store.persist_execution(&value, &[event]).await.unwrap();
    value
}
fn manifest(id: Uuid, source: &Sandbox) -> SnapshotManifest {
    SnapshotManifest {
        format_version: 1,
        id,
        source_sandbox_id: source.id,
        kind: SnapshotKind::MemoryAndDisk,
        driver: source.profile.clone(),
        architecture: "x86_64".into(),
        image_digest: source.image.clone(),
        objects: BTreeMap::from([
            ("state".into(), format!("sha256:{}", "a".repeat(64))),
            ("memory".into(), format!("sha256:{}", "b".repeat(64))),
            ("disk".into(), format!("sha256:{}", "c".repeat(64))),
        ]),
        runtime_version: "fixture-v1".into(),
        created_at: Utc::now(),
    }
}

#[tokio::test]
async fn concurrent_capture_intent_fences_work_and_survives_actual_database_reopen() {
    let directory = tempfile::Builder::new()
        .prefix("gh-snapshot-db-")
        .tempdir()
        .unwrap();
    let path = directory.path().join("state.db");
    let store = Store::open(&path).await.unwrap();
    let (src, _) = source(&store).await;
    let job = running(&store, src.id).await;
    let supported = profile();
    let intent = capture();
    let (left, right) = tokio::join!(
        store.create_snapshot(&supported, src.id, &intent, "same-key"),
        store.create_snapshot(&supported, src.id, &intent, "same-key")
    );
    let first = left.unwrap();
    assert_eq!(first.snapshot.id, right.unwrap().snapshot.id);
    let candidates = store
        .snapshot_execution_candidates(first.snapshot.id)
        .await
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].execution.id, job.id);
    assert_eq!(candidates[0].cursor, 1);
    assert!(store.snapshot_source_fenced(src.id).await.unwrap());
    assert_eq!(
        store
            .create_execution(src.id, &CommandSpec::new(["true"]), "blocked")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    assert_eq!(
        store.cancel_execution(job.id).await.unwrap_err().code,
        ErrorCode::InvalidState
    );
    for desired in [DesiredState::Paused, DesiredState::Running] {
        assert_eq!(
            store
                .set_desired(src.id, desired, "blocked-lifecycle")
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
    }
    assert_eq!(
        store
            .authorize_work(src.id, Capability::Files)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    assert_eq!(
        store
            .require_snapshot_dispatch(src.id)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    let other = source(&store).await.0;
    assert!(
        store
            .create_execution(other.id, &CommandSpec::new(["true"]), "unrelated")
            .await
            .is_ok()
    );
    let changed = CreateSnapshot {
        kind: SnapshotKind::Rootfs,
    };
    assert_eq!(
        store
            .create_snapshot(&profile(), src.id, &changed, "same-key")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let identity = store.installation_id();
    store.close().await;
    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.installation_id(), identity);
    let retry = store
        .create_snapshot(&profile(), src.id, &capture(), "same-key")
        .await
        .unwrap();
    assert_eq!(retry.snapshot.id, first.snapshot.id);
    assert_eq!(retry.operation.id, first.operation.id);
    let candidates = store
        .snapshot_execution_candidates(first.snapshot.id)
        .await
        .unwrap();
    assert_eq!(candidates[0].execution.id, job.id);
    assert_eq!(candidates[0].spec.argv, ["sleep", "120"]);
    assert_eq!(retry.operation.state, OperationState::Pending);
    assert!(store.snapshot_source_fenced(src.id).await.unwrap());
    store
        .fail_unstarted_snapshot(
            first.snapshot.id,
            &ApiError::new(
                ErrorCode::UnsupportedCapability,
                "synthetic pre-dispatch refusal",
            ),
        )
        .await
        .unwrap();
    let failed = store.snapshot_created(first.snapshot.id).await.unwrap();
    assert_eq!(failed.snapshot.state, SnapshotState::Failed);
    assert_eq!(failed.snapshot.cleanup, CleanupState::Complete);
    assert_eq!(failed.operation.state, OperationState::Failed);
    assert!(!store.snapshot_source_fenced(src.id).await.unwrap());
    assert!(store.cancel_execution(job.id).await.is_ok());
    assert!(
        store
            .set_desired(src.id, DesiredState::Paused, "blocked-lifecycle")
            .await
            .is_ok()
    );
    store.close().await;
    let path = directory.path().to_owned();
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn uncertain_dispatched_capture_never_grants_a_second_dispatch_or_erases_source_identity() {
    let directory = tempfile::Builder::new()
        .prefix("gh-snapshot-db-")
        .tempdir()
        .unwrap();
    let path = directory.path().join("state.db");
    let store = Store::open(&path).await.unwrap();
    let (src, handle) = source(&store).await;
    let snapshot = store
        .create_snapshot(&profile(), src.id, &capture(), "capture")
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        store.begin_snapshot_capture(snapshot.snapshot.id, &handle),
        store.begin_snapshot_capture(snapshot.snapshot.id, &handle)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a.first_dispatch, b.first_dispatch);
    assert!(
        store
            .fail_unstarted_snapshot(
                snapshot.snapshot.id,
                &ApiError::new(ErrorCode::Internal, "must not release dispatched work")
            )
            .await
            .is_err()
    );
    store
        .snapshot_capture_unknown(
            snapshot.snapshot.id,
            &ApiError::new(
                ErrorCode::BackendUnavailable,
                "stream EOF is not completion",
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .snapshot(snapshot.snapshot.id)
            .await
            .unwrap()
            .snapshot
            .cleanup,
        CleanupState::Unknown
    );
    let mut changed = handle.clone();
    changed.backend_ref.push_str("changed");
    assert!(
        store
            .begin_snapshot_capture(snapshot.snapshot.id, &changed)
            .await
            .is_err()
    );
    let original = store.sandbox(src.id).await.unwrap();
    let mut replaced = original.clone();
    replaced.handle = Some(changed);
    assert_eq!(
        store.observe(replaced).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    let mut erased = original.clone();
    erased.handle = None;
    assert_eq!(
        store.observe(erased).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(
        store
            .sandbox(src.id)
            .await
            .unwrap()
            .handle
            .unwrap()
            .backend_ref,
        handle.backend_ref
    );
    store.close().await;
    let store = Store::open(&path).await.unwrap();
    let retry = store
        .begin_snapshot_capture(snapshot.snapshot.id, &handle)
        .await
        .unwrap();
    assert!(!retry.first_dispatch && retry.snapshot.dispatched && retry.snapshot.source_fenced);
    assert_eq!(retry.snapshot.snapshot.state, SnapshotState::Unknown);
    assert_eq!(
        store.operation(snapshot.operation.id).await.unwrap().state,
        OperationState::Running
    );
    store.close().await;
    let path = directory.path().to_owned();
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn ready_reference_is_immutable_private_and_original_source_collection_commits_its_own_fence_release()
 {
    let store = Store::memory().await.unwrap();
    let (src, handle) = source(&store).await;
    let snapshot = store
        .create_snapshot(&profile(), src.id, &capture(), "capture")
        .await
        .unwrap();
    let id = snapshot.snapshot.id;
    store.begin_snapshot_capture(id, &handle).await.unwrap();
    let expected = manifest(id, &src);
    let reference = serde_json::json!({"private_worker_reference":"must-not-appear-in-public-response","capture":id});
    let mut wrong = expected.clone();
    wrong.id = Uuid::new_v4();
    assert!(
        store
            .snapshot_capture_ready(id, &handle, &wrong, &reference)
            .await
            .is_err()
    );
    wrong = expected.clone();
    wrong
        .objects
        .insert("disk".into(), "/host/private/path".into());
    assert!(
        store
            .snapshot_capture_ready(id, &handle, &wrong, &reference)
            .await
            .is_err()
    );
    assert!(
        store
            .snapshot_capture_ready(id, &handle, &expected, &serde_json::json!({}))
            .await
            .is_err()
    );
    store
        .snapshot_capture_ready(id, &handle, &expected, &reference)
        .await
        .unwrap();
    store
        .snapshot_capture_ready(id, &handle, &expected, &reference)
        .await
        .unwrap();
    let mut other = reference.clone();
    other["capture"] = serde_json::json!(Uuid::new_v4());
    assert!(
        store
            .snapshot_capture_ready(id, &handle, &expected, &other)
            .await
            .is_err()
    );
    let public = store.snapshot_created(id).await.unwrap();
    let serialized = serde_json::to_string(&public).unwrap();
    assert!(
        !serialized.contains("private_worker_reference")
            && !serialized.contains(&handle.backend_ref)
    );
    assert_eq!(public.snapshot.state, SnapshotState::Ready);
    assert_eq!(public.operation.state, OperationState::Succeeded);
    assert_eq!(public.snapshot.cleanup, CleanupState::Pending);
    assert!(store.snapshot_source_fenced(src.id).await.unwrap());
    store
        .set_desired(src.id, DesiredState::Terminated, "stop-source")
        .await
        .unwrap();
    let mut original = store.sandbox(src.id).await.unwrap();
    original.sandbox.state = SandboxState::Stopping;
    store.observe(original.clone()).await.unwrap();
    original.sandbox.state = SandboxState::Terminated;
    original.sandbox.cleanup = CleanupState::Complete;
    original.handle = None;
    store.observe(original).await.unwrap();
    let settled = store.snapshot(id).await.unwrap();
    assert!(settled.source_collected && !settled.source_fenced);
    assert_eq!(settled.runtime_reference, Some(reference.clone()));
    assert_eq!(settled.snapshot.cleanup, CleanupState::Pending);
    store
        .snapshot_capture_ready(id, &handle, &expected, &reference)
        .await
        .unwrap();
    assert_eq!(
        store.snapshot_created(id).await.unwrap().snapshot.state,
        SnapshotState::Ready
    );
    store.close().await;
}

#[tokio::test]
async fn refused_admission_leaves_no_fence_or_reserved_key_and_requires_settled_dispatch() {
    let store = Store::memory().await.unwrap();
    let (src, _) = source(&store).await;
    let mut unsupported = profile();
    unsupported.capabilities.remove(&Capability::MemorySnapshot);
    assert_eq!(
        store
            .create_snapshot(&unsupported, src.id, &capture(), "retry")
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedCapability
    );
    unsupported = profile();
    unsupported.availability = Availability::Unverified;
    assert_eq!(
        store
            .create_snapshot(&unsupported, src.id, &capture(), "retry")
            .await
            .unwrap_err()
            .code,
        ErrorCode::BackendUnavailable
    );
    assert_eq!(
        store
            .create_snapshot(
                &profile(),
                src.id,
                &CreateSnapshot {
                    kind: SnapshotKind::Volumes
                },
                "retry"
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedCapability
    );
    let mut execution = store
        .create_execution(src.id, &CommandSpec::new(["sleep", "120"]), "command")
        .await
        .unwrap();
    assert_eq!(
        store
            .create_snapshot(&profile(), src.id, &capture(), "retry")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    assert!(!store.snapshot_source_fenced(src.id).await.unwrap());
    assert!(store.snapshot_work().await.unwrap().is_empty());
    execution.state = ExecutionState::Running;
    execution.started_at = Some(Utc::now());
    execution.cleanup = CleanupState::Pending;
    let event = ExecutionEvent {
        execution_id: execution.id,
        sequence: 1,
        timestamp: Utc::now(),
        kind: EventKind::Started,
        data: serde_json::json!({}),
    };
    store.persist_execution(&execution, &[event]).await.unwrap();
    let accepted = store
        .create_snapshot(&profile(), src.id, &capture(), "retry")
        .await
        .unwrap();
    assert_eq!(accepted.snapshot.state, SnapshotState::Pending);
    assert_eq!(store.snapshot_work().await.unwrap().len(), 1);
    store.close().await;
}

#[tokio::test]
async fn actual_v17_database_migration_preserves_installation_and_existing_source_rows() {
    use sqlx::Connection;
    let directory = tempfile::Builder::new()
        .prefix("gh-snapshot-db-")
        .tempdir()
        .unwrap();
    let path = directory.path().join("state.db");
    let store = Store::open(&path).await.unwrap();
    let identity = store.installation_id();
    let (src, handle) = source(&store).await;
    store.close().await;
    let mut connection = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    sqlx::raw_sql("DROP TABLE restored_execution_bindings;DROP TABLE snapshot_restorations;DROP TABLE snapshot_execution_candidates; DROP TABLE snapshots; UPDATE meta SET value='17' WHERE key='schema_version';")
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.installation_id(), identity);
    assert_eq!(
        store
            .sandbox(src.id)
            .await
            .unwrap()
            .handle
            .unwrap()
            .backend_ref,
        handle.backend_ref
    );
    assert!(store.snapshot_work().await.unwrap().is_empty());
    store
        .create_snapshot(&profile(), src.id, &capture(), "after-upgrade")
        .await
        .unwrap();
    store.close().await;
    let path = directory.path().to_owned();
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn v18_migration_and_durable_refusal_release_only_original_dispatch_without_collecting_source()
 {
    use sqlx::Connection;
    let directory = tempfile::Builder::new()
        .prefix("gh-snapshot-refusal-")
        .tempdir()
        .unwrap();
    let path = directory.path().join("state.db");
    let store = Store::open(&path).await.unwrap();
    let installation = store.installation_id();
    let (src, handle) = source(&store).await;
    let execution = running(&store, src.id).await;
    let created = store
        .create_snapshot(&profile(), src.id, &capture(), "original")
        .await
        .unwrap();
    let id = created.snapshot.id;
    let reason = ApiError::new(
        ErrorCode::QuotaExceeded,
        "synthetic durable backend refusal",
    );
    let receipt = serde_json::json!({"capture":id,"source":handle.backend_ref,"private_backend_proof":"synthetic-private-proof"});
    assert!(
        store
            .snapshot_capture_refused(id, &handle, &reason, &receipt)
            .await
            .is_err()
    );
    store.begin_snapshot_capture(id, &handle).await.unwrap();
    store
        .snapshot_capture_unknown(
            id,
            &ApiError::new(ErrorCode::NotFound, "absence is not a refusal"),
        )
        .await
        .unwrap();
    assert!(store.snapshot_source_fenced(src.id).await.unwrap());
    store.close().await;
    let mut connection = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    sqlx::raw_sql("DROP TABLE restored_execution_bindings;DROP TABLE snapshot_restorations;ALTER TABLE snapshots DROP COLUMN collect_operation; ALTER TABLE snapshots DROP COLUMN capture_refusal; UPDATE meta SET value='18' WHERE key='schema_version';").execute(&mut connection).await.unwrap();
    connection.close().await.unwrap();
    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.installation_id(), installation);
    assert!(store.snapshot(id).await.unwrap().capture_refusal.is_none());
    assert_eq!(
        store.snapshot_execution_candidates(id).await.unwrap()[0]
            .execution
            .id,
        execution.id
    );
    let mut foreign = handle.clone();
    foreign.backend_ref.push_str("-foreign");
    assert!(
        store
            .snapshot_capture_refused(id, &foreign, &reason, &receipt)
            .await
            .is_err()
    );
    assert!(
        store
            .snapshot_capture_refused(id, &handle, &reason, &serde_json::json!({}))
            .await
            .is_err()
    );
    assert!(store.snapshot_source_fenced(src.id).await.unwrap());
    store
        .snapshot_capture_refused(id, &handle, &reason, &receipt)
        .await
        .unwrap();
    let stored = store.snapshot(id).await.unwrap();
    assert_eq!(stored.snapshot.state, SnapshotState::Failed);
    assert_eq!(stored.snapshot.cleanup, CleanupState::Complete);
    assert!(!stored.source_fenced && !stored.source_collected);
    assert_eq!(stored.capture_refusal, Some(receipt.clone()));
    assert!(stored.runtime_reference.is_none());
    assert!(store.snapshot_work().await.unwrap().is_empty());
    let original = store.sandbox(src.id).await.unwrap();
    assert_eq!(original.sandbox.state, SandboxState::Running);
    assert_eq!(original.handle.unwrap().backend_ref, handle.backend_ref);
    store
        .authorize_work(src.id, Capability::Files)
        .await
        .unwrap();
    let public = store.snapshot_created(id).await.unwrap();
    assert_eq!(public.operation.state, OperationState::Failed);
    assert_eq!(
        public.snapshot.error.as_ref().unwrap().code,
        ErrorCode::QuotaExceeded
    );
    let body = serde_json::to_string(&public).unwrap();
    assert!(!body.contains("synthetic-private-proof") && !body.contains(&handle.backend_ref));
    store
        .snapshot_capture_refused(id, &handle, &reason, &receipt)
        .await
        .unwrap();
    let changed = ApiError::new(ErrorCode::Internal, "different reason");
    assert!(
        store
            .snapshot_capture_refused(id, &handle, &changed, &receipt)
            .await
            .is_err()
    );
    assert!(
        store
            .snapshot_capture_refused(id, &handle, &reason, &serde_json::json!({"changed":true}))
            .await
            .is_err()
    );
    assert!(
        store
            .snapshot_capture_ready(
                id,
                &handle,
                &manifest(id, &src),
                &serde_json::json!({"synthetic":true})
            )
            .await
            .is_err()
    );
    store.close().await;
    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store.snapshot(id).await.unwrap().capture_refusal,
        Some(receipt)
    );
    assert_eq!(
        store
            .create_snapshot(&profile(), src.id, &capture(), "original")
            .await
            .unwrap()
            .snapshot
            .id,
        id
    );
    let fresh = store
        .create_snapshot(&profile(), src.id, &capture(), "fresh")
        .await
        .unwrap();
    assert_ne!(fresh.snapshot.id, id);
    assert_eq!(fresh.snapshot.state, SnapshotState::Pending);
    assert!(store.snapshot_source_fenced(src.id).await.unwrap());
    store.close().await;
    let mut connection = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    let version: String = sqlx::query_scalar("SELECT value FROM meta WHERE key='schema_version'")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(version, "21");
    connection.close().await.unwrap();
    directory.close().unwrap();
    assert!(!path.exists());
}
