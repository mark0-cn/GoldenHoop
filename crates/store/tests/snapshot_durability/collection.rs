//! Real SQLite state transitions; physical runtime observations are synthetic.
use super::*;

pub(super) async fn explicit_source_collection(store: &Store, id: Uuid) {
    store
        .set_desired(id, DesiredState::Terminated, "explicit-source-collection")
        .await
        .unwrap();
    let mut original = store.sandbox(id).await.unwrap();
    original.sandbox.state = SandboxState::Stopping;
    store.observe(original.clone()).await.unwrap();
    original.sandbox.state = SandboxState::Terminated;
    original.sandbox.cleanup = CleanupState::Complete;
    original.handle = None;
    store.observe(original).await.unwrap();
}

#[tokio::test]
async fn deletion_and_first_dispatch_are_atomic_and_never_implicitly_collect_a_source() {
    let store = Store::memory().await.unwrap();
    for index in 0..8 {
        let (src, handle) = source(&store).await;
        let created = store
            .create_snapshot(&profile(), src.id, &capture(), "capture")
            .await
            .unwrap();
        let id = created.snapshot.id;
        let (deletion, dispatch) = if index % 2 == 0 {
            tokio::join!(
                store.delete_snapshot(id, "delete"),
                store.begin_snapshot_capture(id, &handle)
            )
        } else {
            let (dispatch, deletion) = tokio::join!(
                store.begin_snapshot_capture(id, &handle),
                store.delete_snapshot(id, "delete")
            );
            (deletion, dispatch)
        };
        assert_ne!(deletion.is_ok(), dispatch.is_ok());
        let original = store.sandbox(src.id).await.unwrap();
        assert_eq!(original.sandbox.state, SandboxState::Running);
        assert_eq!(original.sandbox.desired_state, DesiredState::Running);
        assert_eq!(original.handle.unwrap().backend_ref, handle.backend_ref);
        if let Ok(op) = deletion {
            assert_eq!(op.state, OperationState::Succeeded);
            assert_eq!(
                store.snapshot(id).await.unwrap().snapshot.state,
                SnapshotState::Collected
            );
            assert!(!store.snapshot_source_fenced(src.id).await.unwrap());
            assert_eq!(
                store.snapshot_created(id).await.unwrap().operation.state,
                OperationState::Cancelled
            );
            assert_eq!(
                store.delete_snapshot(id, "second-key").await.unwrap().id,
                op.id
            );
            assert!(store.begin_snapshot_capture(id, &handle).await.is_err());
        } else {
            assert!(
                store
                    .snapshot(id)
                    .await
                    .unwrap()
                    .collect_operation
                    .is_none()
            );
            assert!(store.snapshot_source_fenced(src.id).await.unwrap());
            explicit_source_collection(&store, src.id).await;
            assert_eq!(
                store.delete_snapshot(id, "delete").await.unwrap().state,
                OperationState::Pending
            );
        }
        assert_eq!(
            store
                .prior_snapshot_request(src.id, &capture(), "capture")
                .await
                .unwrap()
                .unwrap()
                .snapshot
                .id,
            id
        );
    }
    store.close().await;
}

#[tokio::test]
async fn actual_v19_migration_and_collection_reopen_retain_ready_reference_until_positive_gc() {
    use sqlx::Connection;
    let directory = tempfile::Builder::new()
        .prefix("gh-snapshot-delete-")
        .tempdir()
        .unwrap();
    let path = directory.path().join("state.db");
    let store = Store::open(&path).await.unwrap();
    let installation = store.installation_id();
    let (src, handle) = source(&store).await;
    let created = store
        .create_snapshot(&profile(), src.id, &capture(), "capture")
        .await
        .unwrap();
    let id = created.snapshot.id;
    store.begin_snapshot_capture(id, &handle).await.unwrap();
    let expected = manifest(id, &src);
    let reference = serde_json::json!({"private_immutable_reference":id});
    store
        .snapshot_capture_ready(id, &handle, &expected, &reference)
        .await
        .unwrap();
    assert_eq!(
        store.delete_snapshot(id, "delete").await.unwrap_err().code,
        ErrorCode::InvalidState
    );
    assert!(
        store
            .snapshot(id)
            .await
            .unwrap()
            .collect_operation
            .is_none()
    );
    store.close().await;
    let mut connection = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    sqlx::raw_sql("DROP TABLE restored_execution_bindings;DROP TABLE snapshot_restorations;ALTER TABLE snapshots DROP COLUMN collect_operation; UPDATE meta SET value='19' WHERE key='schema_version';").execute(&mut connection).await.unwrap();
    connection.close().await.unwrap();
    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.installation_id(), installation);
    let migrated = store.snapshot(id).await.unwrap();
    assert!(migrated.source_fenced && migrated.collect_operation.is_none());
    assert_eq!(migrated.runtime_reference, Some(reference.clone()));
    explicit_source_collection(&store, src.id).await;
    let deletion = store.delete_snapshot(id, "delete").await.unwrap();
    assert_eq!(deletion.state, OperationState::Pending);
    assert_eq!(
        store.delete_snapshot(id, "new-key").await.unwrap().id,
        deletion.id
    );
    assert_eq!(
        store
            .snapshot_operation_source(created.operation.id)
            .await
            .unwrap(),
        Some(src.id)
    );
    assert_eq!(
        store.snapshot_operation_source(deletion.id).await.unwrap(),
        Some(src.id)
    );
    assert!(
        store
            .snapshot_capture_ready(id, &handle, &expected, &reference)
            .await
            .is_err()
    );
    store.begin_snapshot_collection(id, &handle).await.unwrap();
    store
        .snapshot_collection_unknown(
            id,
            &ApiError::new(ErrorCode::BackendUnavailable, "synthetic GC reply lost"),
        )
        .await
        .unwrap();
    assert_eq!(
        store.snapshot(id).await.unwrap().snapshot.cleanup,
        CleanupState::Unknown
    );
    assert_eq!(
        store.snapshot(id).await.unwrap().runtime_reference,
        Some(reference.clone())
    );
    assert_eq!(
        store.operation(created.operation.id).await.unwrap().state,
        OperationState::Succeeded
    );
    assert_eq!(
        store.operation(deletion.id).await.unwrap().state,
        OperationState::Running
    );
    store.close().await;
    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store.snapshot(id).await.unwrap().collect_operation,
        Some(deletion.id)
    );
    let mut foreign = handle.clone();
    foreign.backend_ref.push_str("-foreign");
    assert!(
        store
            .complete_snapshot_collection(id, &foreign, None)
            .await
            .is_err()
    );
    assert!(
        store
            .complete_snapshot_collection(
                id,
                &handle,
                Some((
                    &ApiError::new(ErrorCode::Internal, "contradiction"),
                    &serde_json::json!({"refusal":true})
                ))
            )
            .await
            .is_err()
    );
    store.begin_snapshot_collection(id, &handle).await.unwrap();
    store
        .complete_snapshot_collection(id, &handle, None)
        .await
        .unwrap();
    let final_state = store.snapshot(id).await.unwrap();
    assert_eq!(final_state.snapshot.state, SnapshotState::Collected);
    assert_eq!(final_state.snapshot.cleanup, CleanupState::Complete);
    assert!(final_state.runtime_reference.is_none());
    assert!(final_state.snapshot.manifest.is_some());
    assert_eq!(
        store.operation(created.operation.id).await.unwrap().state,
        OperationState::Succeeded
    );
    assert_eq!(
        store.operation(deletion.id).await.unwrap().state,
        OperationState::Succeeded
    );
    store
        .complete_snapshot_collection(id, &handle, None)
        .await
        .unwrap();
    assert_eq!(
        store.delete_snapshot(id, "third-key").await.unwrap().id,
        deletion.id
    );
    assert!(store.snapshot_work().await.unwrap().is_empty());
    store.close().await;
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn unknown_dispatch_deletion_accepts_only_durable_refusal_after_explicit_source_collection() {
    let store = Store::memory().await.unwrap();
    let (src, handle) = source(&store).await;
    let id = store
        .create_snapshot(&profile(), src.id, &capture(), "capture")
        .await
        .unwrap()
        .snapshot
        .id;
    store.begin_snapshot_capture(id, &handle).await.unwrap();
    store
        .snapshot_capture_unknown(
            id,
            &ApiError::new(ErrorCode::NotFound, "absence is not cleanup"),
        )
        .await
        .unwrap();
    assert!(store.delete_snapshot(id, "delete").await.is_err());
    explicit_source_collection(&store, src.id).await;
    let op = store.delete_snapshot(id, "delete").await.unwrap();
    store.begin_snapshot_collection(id, &handle).await.unwrap();
    let reason = ApiError::new(
        ErrorCode::BackendUnavailable,
        "synthetic durable closed intent",
    );
    let receipt = serde_json::json!({"capture":id,"source":handle.backend_ref});
    assert!(
        store
            .complete_snapshot_collection(id, &handle, Some((&reason, &serde_json::json!({}))))
            .await
            .is_err()
    );
    store
        .complete_snapshot_collection(id, &handle, Some((&reason, &receipt)))
        .await
        .unwrap();
    let collected = store.snapshot(id).await.unwrap();
    assert_eq!(collected.capture_refusal, Some(receipt.clone()));
    assert_eq!(collected.snapshot.state, SnapshotState::Collected);
    assert_eq!(
        store.operation(op.id).await.unwrap().state,
        OperationState::Succeeded
    );
    assert_eq!(
        store.snapshot_created(id).await.unwrap().operation.state,
        OperationState::Cancelled
    );
    store
        .complete_snapshot_collection(id, &handle, Some((&reason, &receipt)))
        .await
        .unwrap();
    assert!(
        store
            .complete_snapshot_collection(
                id,
                &handle,
                Some((&reason, &serde_json::json!({"different":true})))
            )
            .await
            .is_err()
    );
    store.close().await;
}

#[tokio::test]
async fn snapshot_pages_are_source_filtered_ordered_and_bounded_after_collection() {
    let store = Store::memory().await.unwrap();
    let (src, _) = source(&store).await;
    let (other, _) = source(&store).await;
    let mut ids = Vec::new();
    for index in 0..4 {
        let id = store
            .create_snapshot(&profile(), src.id, &capture(), &format!("capture-{index}"))
            .await
            .unwrap()
            .snapshot
            .id;
        store.delete_snapshot(id, "delete").await.unwrap();
        ids.push(id);
    }
    store
        .create_snapshot(&profile(), other.id, &capture(), "other")
        .await
        .unwrap();
    ids.sort();
    let first = store.list_snapshots(Some(src.id), None, 2).await.unwrap();
    assert_eq!(
        first.items.iter().map(|s| s.id).collect::<Vec<_>>(),
        ids[..2]
    );
    assert_eq!(first.next_cursor, Some(ids[1]));
    let next = store
        .list_snapshots(Some(src.id), first.next_cursor, 2)
        .await
        .unwrap();
    assert_eq!(
        next.items.iter().map(|s| s.id).collect::<Vec<_>>(),
        ids[2..]
    );
    assert!(next.next_cursor.is_none());
    assert_eq!(
        store
            .list_snapshots(None, None, 100)
            .await
            .unwrap()
            .items
            .len(),
        5
    );
    for limit in [0, 1001] {
        assert!(store.list_snapshots(None, None, limit).await.is_err());
    }
    store.close().await;
}
