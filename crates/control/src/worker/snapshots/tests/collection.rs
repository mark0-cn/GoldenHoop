//! Real worker locks and SQLite; VM and object observations remain synthetic.
use super::*;

async fn remove_source_explicitly(worker: &Worker, id: Uuid) {
    worker
        .store
        .set_desired(id, DesiredState::Terminated, "explicit-source-delete")
        .await
        .unwrap();
    let _guard = worker.lock(id).await.lock_owned().await;
    worker.reconcile(id).await.unwrap();
}

#[tokio::test]
async fn ready_snapshot_deletion_waits_for_explicit_source_collection_and_recovers_lost_gc_reply() {
    checked(|worker, backend, path| async move {
        let (src, _) = source(&worker).await;
        backend.state.store(READY, Ordering::SeqCst);
        let created = worker
            .admit_snapshot(src.id, &intent(), "capture")
            .await
            .unwrap();
        let id = created.snapshot.id;
        step(&worker, id).await.unwrap();
        assert_eq!(
            worker
                .store
                .delete_snapshot(id, "delete")
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(backend.removals.load(Ordering::SeqCst), 0);
        assert_eq!(backend.collections.load(Ordering::SeqCst), 0);
        assert_eq!(
            worker
                .store
                .sandbox(src.id)
                .await
                .unwrap()
                .sandbox
                .desired_state,
            DesiredState::Running
        );
        remove_source_explicitly(&worker, src.id).await;
        assert!(worker.store.snapshot(id).await.unwrap().source_collected);
        assert_eq!(backend.removals.load(Ordering::SeqCst), 1);
        let reference = worker.store.snapshot(id).await.unwrap().runtime_reference;
        let deletion = worker.store.delete_snapshot(id, "delete").await.unwrap();
        backend.lose_collection_reply.store(true, Ordering::SeqCst);
        assert!(step(&worker, id).await.is_err());
        assert!(backend.collected.load(Ordering::SeqCst));
        let uncertain = worker.store.snapshot(id).await.unwrap();
        assert_eq!(uncertain.snapshot.state, SnapshotState::Collecting);
        assert_eq!(uncertain.snapshot.cleanup, CleanupState::Unknown);
        assert_eq!(uncertain.runtime_reference, reference);
        assert_eq!(
            worker.store.operation(deletion.id).await.unwrap().state,
            OperationState::Running
        );
        assert_eq!(
            worker
                .store
                .operation(created.operation.id)
                .await
                .unwrap()
                .state,
            OperationState::Succeeded
        );
        worker.store.close().await;
        let replacement = super::worker(
            Store::open(&path).await.unwrap(),
            backend.clone(),
            worker.artifacts.clone(),
        );
        let result = AssertUnwindSafe(async {
            assert_eq!(
                replacement
                    .store
                    .delete_snapshot(id, "new-key")
                    .await
                    .unwrap()
                    .id,
                deletion.id
            );
            step(&replacement, id).await.unwrap();
            let settled = replacement.store.snapshot(id).await.unwrap();
            assert_eq!(settled.snapshot.state, SnapshotState::Collected);
            assert_eq!(settled.snapshot.cleanup, CleanupState::Complete);
            assert!(settled.runtime_reference.is_none());
            assert_eq!(
                replacement
                    .store
                    .operation(deletion.id)
                    .await
                    .unwrap()
                    .state,
                OperationState::Succeeded
            );
            assert_eq!(
                replacement
                    .store
                    .operation(created.operation.id)
                    .await
                    .unwrap()
                    .state,
                OperationState::Succeeded
            );
            assert_eq!(backend.collections.load(Ordering::SeqCst), 2);
            assert_eq!(backend.removals.load(Ordering::SeqCst), 1);
            assert_eq!(backend.captures.load(Ordering::SeqCst), 1);
            assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
            assert!(replacement.store.snapshot_work().await.unwrap().is_empty());
        })
        .catch_unwind()
        .await;
        replacement.store.close().await;
        drop(replacement);
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    })
    .await;
}

#[tokio::test]
async fn missing_marked_capture_collection_requires_original_refusal_and_never_resubmits() {
    checked(|worker, backend, _| async move {
        let (src, handle) = source(&worker).await;
        let id = worker
            .admit_snapshot(src.id, &intent(), "capture")
            .await
            .unwrap()
            .snapshot
            .id;
        worker
            .store
            .begin_snapshot_capture(id, &handle)
            .await
            .unwrap();
        assert!(step(&worker, id).await.is_err());
        remove_source_explicitly(&worker, src.id).await;
        let deletion = worker.store.delete_snapshot(id, "delete").await.unwrap();
        backend.state.store(REFUSED, Ordering::SeqCst);
        backend.wrong_source.store(true, Ordering::SeqCst);
        assert!(step(&worker, id).await.is_err());
        assert!(
            worker
                .store
                .snapshot(id)
                .await
                .unwrap()
                .capture_refusal
                .is_none()
        );
        assert_eq!(
            worker.store.snapshot(id).await.unwrap().snapshot.cleanup,
            CleanupState::Unknown
        );
        backend.wrong_source.store(false, Ordering::SeqCst);
        step(&worker, id).await.unwrap();
        let settled = worker.store.snapshot(id).await.unwrap();
        assert_eq!(settled.snapshot.state, SnapshotState::Collected);
        assert!(settled.capture_refusal.is_some());
        assert_eq!(
            worker.store.operation(deletion.id).await.unwrap().state,
            OperationState::Succeeded
        );
        assert_eq!(backend.removals.load(Ordering::SeqCst), 1);
        assert_eq!(backend.captures.load(Ordering::SeqCst), 0);
        assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
    })
    .await;
}
