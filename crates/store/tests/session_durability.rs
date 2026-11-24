use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
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
        capabilities: BTreeSet::from([Capability::Commands, Capability::NetworkIsolation]),
        code_languages: Default::default(),
        max_resources: ResourceLimits::default(),
        max_ttl_seconds: 86400,
        reason: None,
    };
    let created = store
        .create_sandbox(
            &profile,
            &CreateSandbox::new("test", "image:test"),
            "source",
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let store = Store::open(&path.join("control.db")).await.unwrap();
    let result = AssertUnwindSafe(test(store.clone())).catch_unwind().await;
    store.close().await;
    drop(store);
    dir.close().unwrap();
    assert!(!path.exists());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn session_identity_control_order_replay_and_atomic_terminal_uncertainty() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let spec = SessionSpec::shell();
        let (first, again) = tokio::join!(
            store.create_session(sandbox, &spec, "session"),
            store.create_session(sandbox, &spec, "session")
        );
        let id = first.unwrap().execution.id;
        assert_eq!(again.unwrap().execution.id, id);
        let ordinary = store
            .create_execution(sandbox, &spec.command, "session")
            .await
            .unwrap();
        assert_ne!(ordinary.id, id);
        assert!(store.session_spec(ordinary.id).await.unwrap().is_none());
        assert_eq!(
            store
                .list_sessions(Some(sandbox), None, 1)
                .await
                .unwrap()
                .items
                .len(),
            1
        );
        let mut changed = spec.clone();
        changed.terminal = Some(TerminalSize {
            rows: 24,
            columns: 80,
        });
        assert_eq!(
            store
                .create_session(sandbox, &changed, "session")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let control = SessionControl {
            sequence: 1,
            action: SessionAction::Write {
                data_base64: STANDARD.encode(b"echo once\n"),
            },
        };
        let (a, b) = tokio::join!(
            store.enqueue_session_control(id, &control),
            store.enqueue_session_control(id, &control)
        );
        assert_eq!(
            serde_json::to_value(a.unwrap()).unwrap(),
            serde_json::to_value(b.unwrap()).unwrap()
        );
        let mut altered = control.clone();
        altered.action = SessionAction::CloseInput;
        assert_eq!(
            store
                .enqueue_session_control(id, &altered)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        altered.sequence = 3;
        assert_eq!(
            store
                .enqueue_session_control(id, &altered)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert_eq!(store.session_control_work(id).await.unwrap().len(), 1);
        let receipt = SessionControlReceipt {
            execution_id: id,
            sequence: 1,
            state: SessionControlState::Applied,
            observed_at: Utc::now(),
            error: None,
        };
        store.observe_session_control(&receipt).await.unwrap();
        store.observe_session_control(&receipt).await.unwrap();
        let mut tampered = receipt.clone();
        tampered.state = SessionControlState::Unknown;
        tampered.error = Some(ApiError::new(ErrorCode::BackendUnavailable, "lost"));
        assert_eq!(
            store
                .observe_session_control(&tampered)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let close = SessionControl {
            sequence: 2,
            action: SessionAction::CloseInput,
        };
        store.enqueue_session_control(id, &close).await.unwrap();
        store.cancel_execution(id).await.unwrap();
        store
            .finish_execution(
                id,
                ExecutionState::Cancelled,
                "whole runtime cleanup confirmed",
            )
            .await
            .unwrap();
        assert_eq!(
            store.session_control(id, 1).await.unwrap().receipt.state,
            SessionControlState::Applied
        );
        assert_eq!(
            store.session_control(id, 2).await.unwrap().receipt.state,
            SessionControlState::Unknown
        );
        assert!(store.session_control_work(id).await.unwrap().is_empty());
        assert_eq!(
            store
                .enqueue_session_control(id, &close)
                .await
                .unwrap()
                .state,
            SessionControlState::Unknown
        );
        altered.sequence = 3;
        assert_eq!(
            store
                .enqueue_session_control(id, &altered)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store.session(id).await.unwrap().execution.cleanup,
            CleanupState::Complete
        );
    })
    .await;
}

#[tokio::test]
async fn session_input_quota_rejection_rolls_back_the_sequence_reservation() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let id = store
            .create_session(sandbox, &SessionSpec::shell(), "session")
            .await
            .unwrap()
            .execution
            .id;
        let action = SessionAction::Write {
            data_base64: STANDARD.encode(vec![0; 65536]),
        };
        for sequence in 1..=16 {
            store
                .enqueue_session_control(
                    id,
                    &SessionControl {
                        sequence,
                        action: action.clone(),
                    },
                )
                .await
                .unwrap();
        }
        assert_eq!(
            store
                .enqueue_session_control(
                    id,
                    &SessionControl {
                        sequence: 17,
                        action: SessionAction::Write {
                            data_base64: STANDARD.encode(b"x")
                        }
                    }
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let close = store
            .enqueue_session_control(
                id,
                &SessionControl {
                    sequence: 17,
                    action: SessionAction::CloseInput,
                },
            )
            .await
            .unwrap();
        assert_eq!(close.state, SessionControlState::Pending);
        assert!(store.session_control(id, 18).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn schema_two_migration_and_actual_reopen_preserve_pending_input_and_identities() {
    use sqlx::{
        Connection,
        sqlite::{SqliteConnectOptions, SqliteConnection},
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let db_path = path.join("control.db");
    let store = Store::open(&db_path).await.unwrap();
    let setup = AssertUnwindSafe(async {
        let sandbox = source(&store).await;
        let command = store
            .create_execution(sandbox, &CommandSpec::new(["true"]), "existing")
            .await
            .unwrap();
        let artifact = store
            .create_artifact(sandbox, &CreateArtifact::new("old.bin"), "old-artifact")
            .await
            .unwrap();
        (
            store.installation_id(),
            sandbox,
            command.id,
            artifact.artifact.id,
            artifact.operation.id,
        )
    })
    .catch_unwind()
    .await;
    store.close().await;
    drop(store);
    let result=AssertUnwindSafe(async {
        let (installation,sandbox,command,artifact,artifact_operation)=setup.unwrap();
        // A consistent schema-2 fixture with existing resources and no session tables.
        let mut connection=SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&db_path)).await.unwrap();
        let modifying=sqlx::raw_sql("DROP TABLE sandbox_scopes;DROP TABLE code_context_events; DROP TABLE code_context_sources; DROP TABLE code_runs; DROP TABLE code_contexts; DROP TABLE session_controls; DROP TABLE sessions; UPDATE meta SET value='2' WHERE key='schema_version'").execute(&mut connection).await;
        connection.close().await.unwrap();
        modifying.unwrap();
        let migrated=Store::open(&db_path).await.unwrap();
        let creating=AssertUnwindSafe(async {
            assert_eq!(migrated.installation_id(),installation);
            assert_eq!(migrated.artifact(artifact).await.unwrap().artifact.source_path,"old.bin");
            assert_eq!(migrated.operation(artifact_operation).await.unwrap().resource_id,artifact);
            assert_eq!(migrated.execution(command).await.unwrap().execution.sandbox_id,sandbox);
            let spec=SessionSpec {command:CommandSpec::new(["/bin/sh"]),terminal:Some(TerminalSize {rows:30,columns:90})};
            let session=migrated.create_session(sandbox,&spec,"session").await.unwrap();
            migrated.enqueue_session_control(session.execution.id,&SessionControl {sequence:1,action:SessionAction::Write {data_base64:STANDARD.encode(b"\x00\xff\n")}}).await.unwrap();
            session.execution.id
        }).catch_unwind().await;
        migrated.close().await;drop(migrated);
        let id=creating.unwrap();
        let reopened=Store::open(&db_path).await.unwrap();
        let checking=AssertUnwindSafe(async {
            assert_eq!(reopened.installation_id(),installation);
            let session=reopened.session(id).await.unwrap();
            assert_eq!(session.spec.terminal,Some(TerminalSize {rows:30,columns:90}));
            let work=reopened.session_control_work(id).await.unwrap();
            assert_eq!(work.len(),1);
            assert!(matches!(&work[0].request.action,SessionAction::Write {data_base64} if data_base64==&STANDARD.encode(b"\x00\xff\n")));
            reopened.finish_execution(id,ExecutionState::Failed,"runtime absent after crash").await.unwrap();
            assert_eq!(reopened.session_control(id,1).await.unwrap().receipt.state,SessionControlState::Unknown);
        }).catch_unwind().await;
        reopened.close().await;drop(reopened);checking.unwrap();
    }).catch_unwind().await;
    dir.close().unwrap();
    assert!(!path.exists());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
