//! Actual SQLite transactions and reopen; runtime observations are synthetic.
use super::*;

async fn ready(store: &Store, source: &Sandbox, handle: &RuntimeHandle) -> Uuid {
    let id = store
        .create_snapshot(
            &profile(),
            source.id,
            &capture(),
            &Uuid::new_v4().to_string(),
        )
        .await
        .unwrap()
        .snapshot
        .id;
    store.begin_snapshot_capture(id, handle).await.unwrap();
    let mut m = manifest(id, source);
    m.created_at = store.snapshot(id).await.unwrap().snapshot.created_at;
    store
        .snapshot_capture_ready(
            id,
            handle,
            &m,
            &serde_json::json!({"private":"retained-reference","capture":id}),
        )
        .await
        .unwrap();
    id
}
fn request(source: &Sandbox) -> RestoreSnapshot {
    let mut target = CreateSandbox::new(source.profile.clone(), source.image.clone());
    target.resources = source.resources.clone();
    target
        .metadata
        .insert("purpose".into(), "new-target".into());
    RestoreSnapshot { target }
}
async fn activate(store: &Store, id: Uuid) -> RuntimeHandle {
    store.begin_restoration(id).await.unwrap();
    let handle = RuntimeHandle {
        sandbox_id: id,
        profile: profile().id,
        backend_ref: format!("new-target-generation-{}", Uuid::new_v4()),
    };
    store.bind_restoration_handle(id, &handle).await.unwrap();
    store.activate_restoration(id, &handle).await.unwrap();
    handle
}

#[tokio::test]
async fn v20_upgrade_restoration_and_retained_binding_survive_reopen_without_source_identity_reuse()
{
    let directory = tempfile::Builder::new()
        .prefix("gh-restore-db-")
        .tempdir()
        .unwrap();
    let root = directory.path().to_owned();
    let path = root.join("state.db");
    use futures_util::FutureExt;
    let mut pools = Vec::new();
    let outcome=std::panic::AssertUnwindSafe(async {
    let store = Store::open(&path).await.unwrap();
    pools.push(store.clone());
    let installation = store.installation_id();
    let (src, handle) = source(&store).await;
    let old = running(&store, src.id).await;
    let snapshot = ready(&store, &src, &handle).await;
    assert_eq!(
        store
            .create_restoration(&profile(), snapshot, &request(&src), "restore")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    super::collection::explicit_source_collection(&store, src.id).await;
    store
        .finish_execution(
            old.id,
            ExecutionState::Cancelled,
            "source was physically collected",
        )
        .await
        .unwrap();
    store.close().await;
    use sqlx::Connection;
    let mut connection = sqlx::SqliteConnection::connect(&format!("sqlite:{}", path.display()))
        .await
        .unwrap();
    let migrated=sqlx::raw_sql("DROP TABLE restored_execution_bindings;DROP TABLE snapshot_restorations;UPDATE meta SET value='20' WHERE key='schema_version';").execute(&mut connection).await;
    connection.close().await.unwrap();
    migrated.unwrap();
    let store = Store::open(&path).await.unwrap();
    pools.push(store.clone());
    assert_eq!(store.installation_id(), installation);
    let intent = request(&src);
    let supported = profile();
    let (a, b) = tokio::join!(
        store.create_restoration(&supported, snapshot, &intent, "restore"),
        store.create_restoration(&supported, snapshot, &intent, "restore")
    );
    let restored = a.unwrap();
    assert_eq!(restored.sandbox.id, b.unwrap().sandbox.id);
    let target = restored.sandbox.id;
    assert_ne!(target, src.id);
    assert_eq!(restored.executions.len(), 1);
    let eid = restored.executions[0].execution.id;
    assert_ne!(eid, old.id);
    assert_eq!(restored.executions[0].source_execution_id, old.id);
    let binding = store
        .restored_execution_binding(eid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            binding.agent_id,
            binding.agent_sandbox_id,
            binding.event_offset
        ),
        (old.id, src.id, 1)
    );
    assert_eq!(
        store.snapshot(restored.snapshot_id).await.unwrap().snapshot.source_sandbox_id, src.id
    );
    assert_eq!(
        store
            .create_execution(target, &CommandSpec::new(["true"]), "too-early")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    let mut bad = store.sandbox(target).await.unwrap();
    bad.sandbox.state = SandboxState::Starting;
    store.observe(bad.clone()).await.unwrap();
    bad.sandbox.state = SandboxState::Running;
    assert_eq!(
        store.observe(bad).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(
        store
            .delete_snapshot(snapshot, "held-delete")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    assert!(
        store
            .idempotent_resource(
                &format!("snapshots:{snapshot}:delete"),
                "held-delete",
                &goldenhoop_store::fingerprint(&()).unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    let runtime = activate(&store, target).await;
    store.cancel_execution(eid).await.unwrap();
    assert!(store.execution(eid).await.unwrap().cancel_requested);
    assert!(!store.execution(old.id).await.unwrap().cancel_requested);
    store
        .authorize_work(target, Capability::Commands)
        .await
        .unwrap();
    store.close().await;
    let store = Store::open(&path).await.unwrap();
    pools.push(store.clone());
    let retry = store
        .prior_restoration(snapshot, &intent, "restore")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (retry.sandbox.id, retry.operation.id),
        (target, restored.operation.id)
    );
    assert_eq!(retry.operation.state, OperationState::Succeeded);
    assert_eq!(
        store
            .restoration(target)
            .await
            .unwrap()
            .unwrap()
            .handle
            .unwrap()
            .backend_ref,
        runtime.backend_ref
    );
    let mut changed = intent.clone();
    changed
        .target
        .metadata
        .insert("changed".into(), "yes".into());
    assert_eq!(
        store
            .create_restoration(&profile(), snapshot, &changed, "restore")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        store
            .create_restoration(&profile(), snapshot, &intent, "different-key")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let mut erased = store.sandbox(target).await.unwrap();
    erased.sandbox.state = SandboxState::Failed;
    erased.sandbox.cleanup = CleanupState::Complete;
    erased.handle = None;
    assert_eq!(
        store.observe(erased).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    store.restoration_collected(target).await.unwrap();
    super::collection::explicit_source_collection(&store, target).await;
    assert_eq!(
        store.operation(restored.operation.id).await.unwrap().state,
        OperationState::Succeeded
    );
    assert!(store.delete_snapshot(snapshot, "held-delete").await.is_ok());
    assert!(
        store
            .snapshot(snapshot)
            .await
            .unwrap()
            .runtime_reference
            .is_some()
    );
    assert_eq!(
        store
            .create_restoration(&profile(), snapshot, &intent, "after-delete")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    store.close().await;
    }).catch_unwind().await;
    for pool in pools {
        pool.close().await;
    }
    directory.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn restoration_and_snapshot_deletion_serialize_before_any_new_target_or_content_gc() {
    let store = Store::memory().await.unwrap();
    for _ in 0..8 {
        let (src, handle) = source(&store).await;
        let snapshot = ready(&store, &src, &handle).await;
        super::collection::explicit_source_collection(&store, src.id).await;
        let intent = request(&src);
        let supported = profile();
        let (restored, deleted) = tokio::join!(
            store.create_restoration(&supported, snapshot, &intent, "race"),
            store.delete_snapshot(snapshot, "race")
        );
        assert_ne!(restored.is_ok(), deleted.is_ok());
        if let Ok(restored) = restored {
            assert_eq!(deleted.unwrap_err().code, ErrorCode::InvalidState);
            assert!(
                !store
                    .restoration(restored.sandbox.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .dispatched
            );
            store
                .restoration_collected(restored.sandbox.id)
                .await
                .unwrap();
        } else {
            assert_eq!(restored.unwrap_err().code, ErrorCode::InvalidState);
            assert_eq!(
                store.snapshot(snapshot).await.unwrap().snapshot.state,
                SnapshotState::Collecting
            );
        }
        assert_eq!(
            store.sandbox(src.id).await.unwrap().sandbox.cleanup,
            CleanupState::Complete
        );
    }
    store.close().await;
}

#[tokio::test]
async fn a_second_continuation_preserves_the_original_agent_id_and_composes_event_offsets() {
    let store = Store::memory().await.unwrap();
    let (src, handle) = source(&store).await;
    let first = running(&store, src.id).await;
    let snapshot = ready(&store, &src, &handle).await;
    super::collection::explicit_source_collection(&store, src.id).await;
    let restored = store
        .create_restoration(&profile(), snapshot, &request(&src), "first")
        .await
        .unwrap();
    let target = restored.sandbox.id;
    let second = restored.executions[0].execution.clone();
    let target_handle = activate(&store, target).await;
    let mut record = store.execution(second.id).await.unwrap().execution;
    record.state = ExecutionState::Running;
    store
        .persist_execution(
            &record,
            &[ExecutionEvent {
                sequence: 1,
                execution_id: second.id,
                timestamp: Utc::now(),
                kind: EventKind::Stdout,
                data: serde_json::json!({"retained":"output"}),
            }],
        )
        .await
        .unwrap();
    let target_source = store.sandbox(target).await.unwrap().sandbox;
    let snapshot2 = ready(&store, &target_source, &target_handle).await;
    store.restoration_collected(target).await.unwrap();
    super::collection::explicit_source_collection(&store, target).await;
    let next = store
        .create_restoration(&profile(), snapshot2, &request(&target_source), "second")
        .await
        .unwrap();
    let third = &next.executions[0];
    let binding = store
        .restored_execution_binding(third.execution.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(third.source_execution_id, second.id);
    assert_ne!(third.execution.id, second.id);
    assert_eq!(
        (
            binding.agent_id,
            binding.agent_sandbox_id,
            binding.event_offset
        ),
        (first.id, src.id, 2)
    );
    assert_eq!(
        store
            .snapshot(next.snapshot_id)
            .await
            .unwrap()
            .snapshot
            .source_sandbox_id,
        target
    );
    store.close().await;
}
