use futures_util::FutureExt;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use std::{collections::BTreeSet, future::Future, panic::AssertUnwindSafe};
use uuid::Uuid;

async fn source(store: &Store) -> Uuid {
    let profile = RuntimeProfile {
        id: "test".into(),
        placement: Placement::Local,
        isolation: Isolation::Gvisor,
        availability: Availability::Available,
        capabilities: BTreeSet::from([Capability::Files, Capability::NetworkIsolation]),
        max_resources: ResourceLimits::default(),
        max_ttl_seconds: 86400,
        reason: None,
    };
    let created = store
        .create_sandbox(
            &profile,
            &CreateSandbox::new("test", "image:test"),
            &Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
    let mut stored = store.sandbox(created.sandbox.id).await.unwrap();
    stored.sandbox.state = SandboxState::Starting;
    store.observe(stored.clone()).await.unwrap();
    stored.sandbox.state = SandboxState::Running;
    store.observe(stored).await.unwrap();
    created.sandbox.id
}
async fn checked<F, Fut>(test: F)
where
    F: FnOnce(Store) -> Fut,
    Fut: Future<Output = ()>,
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let store = Store::open(&path.join("control.db")).await.unwrap();
    let result = AssertUnwindSafe(test(store.clone())).catch_unwind().await;
    store.close().await;
    drop(store);
    directory.close().unwrap();
    assert!(!path.exists());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn immutable_metadata_atomic_completion_delete_race_and_no_resurrection() {
    checked(|store| async move {
        store.bind_artifact_backend(&"a".repeat(64)).await.unwrap();
        store.bind_artifact_backend(&"a".repeat(64)).await.unwrap();
        assert_eq!(
            store
                .bind_artifact_backend(&"b".repeat(64))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let sandbox = source(&store).await;
        let request = CreateArtifact::new("result.bin");
        let (first, repeated) = tokio::join!(
            store.create_artifact(sandbox, &request, "once"),
            store.create_artifact(sandbox, &request, "once")
        );
        let first = first.unwrap();
        assert_eq!(first.artifact.id, repeated.unwrap().artifact.id);
        let id = first.artifact.id;
        assert!(
            store
                .observe_artifact(id, ArtifactState::Available, CleanupState::Pending, None)
                .await
                .is_err()
        );
        let sha = "a".repeat(64);
        store.prepare_artifact(id, &sha, 3).await.unwrap();
        assert_eq!(
            store
                .prepare_artifact(id, &"b".repeat(64), 3)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        store
            .observe_artifact(id, ArtifactState::Available, CleanupState::Pending, None)
            .await
            .unwrap();
        assert_eq!(
            store.operation(first.operation.id).await.unwrap().state,
            OperationState::Succeeded
        );
        let deletion = store.delete_artifact(id, "delete").await.unwrap();
        assert_eq!(
            deletion.id,
            store.delete_artifact(id, "delete-again").await.unwrap().id
        );
        let late = store
            .observe_artifact(id, ArtifactState::Available, CleanupState::Pending, None)
            .await
            .unwrap();
        assert_eq!(late.state, ArtifactState::Deleting);
        assert_eq!(late.desired_state, ArtifactDesiredState::Deleted);
        assert!(
            store
                .observe_artifact(id, ArtifactState::Deleted, CleanupState::Unknown, None)
                .await
                .is_err()
        );
        store
            .observe_artifact(id, ArtifactState::Deleted, CleanupState::Complete, None)
            .await
            .unwrap();
        assert_eq!(
            store.operation(deletion.id).await.unwrap().state,
            OperationState::Succeeded
        );
        assert_eq!(
            store.operation(first.operation.id).await.unwrap().state,
            OperationState::Succeeded
        );
        assert!(
            store
                .observe_artifact(id, ArtifactState::Available, CleanupState::Pending, None)
                .await
                .is_err()
        );
        store.note_artifact_residue(id).await.unwrap();
        let residue = store.artifact(id).await.unwrap().artifact;
        assert_eq!(residue.state, ArtifactState::Deleted);
        assert_eq!(residue.cleanup, CleanupState::Unknown);
        assert_eq!(store.artifact_work().await.unwrap().len(), 1);
        store
            .observe_artifact(id, ArtifactState::Deleted, CleanupState::Complete, None)
            .await
            .unwrap();
        assert_eq!(
            store.operation(deletion.id).await.unwrap().state,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .artifact_created(id)
                .await
                .unwrap()
                .artifact
                .sha256
                .as_deref(),
            Some(sha.as_str())
        );
    })
    .await;
}

#[tokio::test]
async fn upload_and_pending_delete_survive_real_database_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let database = path.join("control.db");
    let store = Store::open(&database).await.unwrap();
    let setup = AssertUnwindSafe(async {
        let sandbox = source(&store).await;
        let created = store
            .create_artifact(sandbox, &CreateArtifact::new("a"), "create")
            .await
            .unwrap();
        store
            .prepare_artifact(created.artifact.id, &"a".repeat(64), 0)
            .await
            .unwrap();
        let deleted = store
            .delete_artifact(created.artifact.id, "delete")
            .await
            .unwrap();
        (created, deleted)
    })
    .catch_unwind()
    .await;
    store.close().await;
    drop(store);
    if let Err(panic) = setup {
        directory.close().unwrap();
        std::panic::resume_unwind(panic);
    }
    let (created, deleted) = setup.unwrap();
    let reopened = Store::open(&database).await.unwrap();
    let result = AssertUnwindSafe(async {
        let record = reopened.artifact(created.artifact.id).await.unwrap();
        assert_eq!(record.artifact.state, ArtifactState::Deleting);
        assert_eq!(record.artifact.size_bytes, Some(0));
        assert_eq!(
            reopened
                .operation(created.operation.id)
                .await
                .unwrap()
                .state,
            OperationState::Cancelled
        );
        assert_eq!(reopened.artifact_work().await.unwrap().len(), 1);
        // Cleanup of a failed in-flight upload satisfies a concurrent delete.
        reopened
            .observe_artifact(
                created.artifact.id,
                ArtifactState::Failed,
                CleanupState::Complete,
                Some(ApiError::new(ErrorCode::NotFound, "source disappeared")),
            )
            .await
            .unwrap();
        assert_eq!(
            reopened.operation(deleted.id).await.unwrap().state,
            OperationState::Succeeded
        );
        assert_eq!(
            reopened
                .artifact(created.artifact.id)
                .await
                .unwrap()
                .artifact
                .state,
            ArtifactState::Deleted
        );
        assert!(reopened.artifact_work().await.unwrap().is_empty());
    })
    .catch_unwind()
    .await;
    reopened.close().await;
    drop(reopened);
    directory.close().unwrap();
    assert!(!path.exists());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn unconfirmed_cleanup_retains_quota_and_failed_reservations_roll_back() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let request = CreateArtifact::new("a");
        let mut ids = Vec::new();
        for n in 0..256 {
            ids.push(
                store
                    .create_artifact(sandbox, &request, &format!("item-{n}"))
                    .await
                    .unwrap()
                    .artifact
                    .id,
            );
        }
        store
            .observe_artifact(
                ids[0],
                ArtifactState::Failed,
                CleanupState::Unknown,
                Some(ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "cleanup unavailable",
                )),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .create_artifact(sandbox, &request, "overflow")
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        store
            .observe_artifact(
                ids[0],
                ArtifactState::Failed,
                CleanupState::Complete,
                Some(ApiError::new(ErrorCode::NotFound, "source absent")),
            )
            .await
            .unwrap();
        store
            .create_artifact(sandbox, &request, "overflow")
            .await
            .unwrap();
        let page = store.list_artifacts(Some(sandbox), None, 10).await.unwrap();
        assert_eq!(page.items.len(), 10);
        assert!(page.next_cursor.is_some());
        assert_eq!(
            store
                .list_artifacts(Some(Uuid::new_v4()), None, 10)
                .await
                .unwrap()
                .items
                .len(),
            0
        );
    })
    .await;
}

#[tokio::test]
async fn schema_one_migration_preserves_existing_identity_and_operation() {
    use sqlx::{Connection, sqlite::SqliteConnectOptions};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let database = path.join("control.db");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(options.open(&database).unwrap());
    let mut connection =
        sqlx::SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&database))
            .await
            .unwrap();
    let setup=AssertUnwindSafe(async {
    sqlx::raw_sql(include_str!("../src/schema.sql"))
        .execute(&mut connection)
        .await
        .unwrap();
    let installation = Uuid::new_v4();
    let sandbox_id = Uuid::new_v4();
    let op_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let request = CreateSandbox::new("test", "image:test");
    let sandbox = Sandbox {
        id: sandbox_id,
        profile: "test".into(),
        image: "image:test".into(),
        state: SandboxState::Running,
        desired_state: DesiredState::Running,
        cleanup: CleanupState::Pending,
        created_at: now,
        expires_at: now + chrono::Duration::minutes(30),
        observed_at: Some(now),
        resources: request.resources.clone(),
        metadata: Default::default(),
        reason: None,
    };
    let operation = Operation {
        id: op_id,
        resource_id: sandbox_id,
        state: OperationState::Succeeded,
        created_at: now,
        finished_at: Some(now),
        error: None,
    };
    sqlx::query("INSERT INTO meta VALUES('schema_version','1'),('installation_id',?)")
        .bind(installation.to_string())
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sandboxes(id,desired,state,cleanup,payload,request,ever_running,cpu_millis,memory_bytes,pids,create_operation) VALUES(?,'running','running','pending',?,?,1,1000,1073741824,256,?)")
        .bind(sandbox_id.to_string()).bind(serde_json::to_string(&sandbox).unwrap()).bind(serde_json::to_string(&request).unwrap()).bind(op_id.to_string()).execute(&mut connection).await.unwrap();
    sqlx::query("INSERT INTO operations VALUES(?,?,'create','succeeded',?)")
        .bind(op_id.to_string())
        .bind(sandbox_id.to_string())
        .bind(serde_json::to_string(&operation).unwrap())
        .execute(&mut connection)
        .await
        .unwrap();
    (installation,sandbox_id,op_id)
    }).catch_unwind().await;
    connection.close().await.unwrap();
    let (installation, sandbox_id, op_id) = match setup {
        Ok(value) => value,
        Err(panic) => {
            directory.close().unwrap();
            std::panic::resume_unwind(panic);
        }
    };
    let store = Store::open(&database).await.unwrap();
    let result = AssertUnwindSafe(async {
        assert_eq!(store.installation_id(), installation);
        assert_eq!(
            store.operation(op_id).await.unwrap().resource_id,
            sandbox_id
        );
        let created = store
            .create_artifact(sandbox_id, &CreateArtifact::new("a"), "create")
            .await
            .unwrap();
        assert_eq!(
            store
                .operation(created.operation.id)
                .await
                .unwrap()
                .resource_id,
            created.artifact.id
        );
    })
    .catch_unwind()
    .await;
    store.close().await;
    drop(store);
    directory.close().unwrap();
    assert!(!path.exists());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
