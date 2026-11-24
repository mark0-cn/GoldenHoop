use std::{collections::BTreeSet, panic::AssertUnwindSafe};

use chrono::{Duration, Utc};
use futures_util::FutureExt;
use goldenhoop_protocol::*;
use goldenhoop_store::*;
use uuid::Uuid;

fn profile() -> RuntimeProfile {
    RuntimeProfile {
        id: "test-profile".into(),
        placement: Placement::Local,
        isolation: Isolation::Gvisor,
        availability: Availability::Available,
        capabilities: BTreeSet::from([
            Capability::Commands,
            Capability::Files,
            Capability::Pause,
            Capability::NetworkIsolation,
        ]),
        code_languages: Default::default(),
        max_resources: ResourceLimits {
            cpu_millis: 16000,
            memory_bytes: 32 * 1024 * 1024 * 1024,
            pids: 4096,
        },
        max_ttl_seconds: 86400,
        reason: None,
    }
}
fn request() -> CreateSandbox {
    serde_json::from_value(
        serde_json::json!({"profile":"test-profile","image":"workload@sha256:test"}),
    )
    .unwrap()
}
fn spec() -> CommandSpec {
    serde_json::from_value(serde_json::json!({"argv":["printf","hello"]})).unwrap()
}
async fn running(store: &Store) -> Sandbox {
    let created = store
        .create_sandbox(&profile(), &request(), &Uuid::new_v4().to_string())
        .await
        .unwrap();
    let mut stored = store.sandbox(created.sandbox.id).await.unwrap();
    stored.sandbox.state = SandboxState::Starting;
    store.observe(stored.clone()).await.unwrap();
    stored.sandbox.state = SandboxState::Running;
    store.observe(stored).await.unwrap();
    store
        .finish_operations(
            created.sandbox.id,
            "create",
            OperationState::Succeeded,
            None,
        )
        .await
        .unwrap();
    store.sandbox(created.sandbox.id).await.unwrap().sandbox
}
fn event(record: &Execution, sequence: u64, kind: EventKind) -> ExecutionEvent {
    ExecutionEvent {
        sequence,
        execution_id: record.id,
        timestamp: Utc::now(),
        kind,
        data: if kind == EventKind::Completed {
            serde_json::to_value(record).unwrap()
        } else {
            serde_json::json!({})
        },
    }
}

#[tokio::test]
async fn concurrent_idempotency_and_failed_reservation_rollback() {
    let store = Store::memory().await.unwrap();
    let profile = profile();
    let mut request = request();
    request.resources.cpu_millis = 16000;
    let (left, right) = tokio::join!(
        store.create_sandbox(&profile, &request, "same-key"),
        store.create_sandbox(&profile, &request, "same-key")
    );
    let left = left.unwrap();
    assert_eq!(left.sandbox.id, right.unwrap().sandbox.id);
    let mut changed = request.clone();
    changed.resources.cpu_millis = 1000;
    assert_eq!(
        store
            .create_sandbox(&profile, &changed, "same-key")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        store
            .create_sandbox(&profile, &changed, "retry-after-cleanup")
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let mut failed = store.sandbox(left.sandbox.id).await.unwrap();
    failed.sandbox.state = SandboxState::Failed;
    failed.sandbox.cleanup = CleanupState::Unknown;
    store.observe(failed.clone()).await.unwrap();
    assert_eq!(
        store
            .create_sandbox(&profile, &changed, "retry-after-cleanup")
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    failed.sandbox.cleanup = CleanupState::Complete;
    store.observe(failed).await.unwrap();
    store
        .create_sandbox(&profile, &changed, "retry-after-cleanup")
        .await
        .unwrap();
    store.close().await;
}

#[tokio::test]
async fn stale_observation_preserves_desired_termination_and_absolute_expiry() {
    let store = Store::memory().await.unwrap();
    let sandbox = running(&store).await;
    let mut stale = store.sandbox(sandbox.id).await.unwrap();
    let delete = store
        .set_desired(sandbox.id, DesiredState::Terminated, "delete")
        .await
        .unwrap();
    assert_eq!(
        store
            .set_desired(sandbox.id, DesiredState::Terminated, "another-delete-key")
            .await
            .unwrap()
            .id,
        delete.id
    );
    stale.sandbox.expires_at += Duration::days(1);
    stale.sandbox.image = "changed".into();
    store.observe(stale).await.unwrap();
    let observed = store.sandbox(sandbox.id).await.unwrap();
    assert_eq!(observed.sandbox.desired_state, DesiredState::Terminated);
    assert_eq!(observed.sandbox.expires_at, sandbox.expires_at);
    assert_eq!(observed.sandbox.image, sandbox.image);
    assert_eq!(
        store
            .finish_operations(sandbox.id, "terminate", OperationState::Succeeded, None)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    let mut stopped = observed;
    stopped.sandbox.state = SandboxState::Stopping;
    store.observe(stopped.clone()).await.unwrap();
    stopped.sandbox.state = SandboxState::Terminated;
    stopped.sandbox.cleanup = CleanupState::Unknown;
    assert_eq!(
        store.observe(stopped.clone()).await.unwrap_err().code,
        ErrorCode::InvalidState
    );
    stopped.sandbox.cleanup = CleanupState::Complete;
    store.observe(stopped).await.unwrap();
    store
        .finish_operations(sandbox.id, "terminate", OperationState::Succeeded, None)
        .await
        .unwrap();
    assert_eq!(
        store.operation(delete.id).await.unwrap().state,
        OperationState::Succeeded
    );
    assert_eq!(
        store
            .set_desired(sandbox.id, DesiredState::Running, "cannot-revive")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    store.close().await;
}

#[tokio::test]
async fn terminal_result_requires_atomic_completion_and_confirmed_cleanup() {
    let store = Store::memory().await.unwrap();
    let sandbox = running(&store).await;
    let mut record = store
        .create_execution(sandbox.id, &spec(), "command")
        .await
        .unwrap();
    assert_eq!(
        store
            .create_execution(sandbox.id, &spec(), "command")
            .await
            .unwrap()
            .id,
        record.id
    );
    record.state = ExecutionState::Succeeded;
    record.exit_code = Some(0);
    record.cleanup = CleanupState::Complete;
    record.finished_at = Some(Utc::now());
    assert_eq!(
        store
            .persist_execution(&record, &[])
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    assert_eq!(store.execution(record.id).await.unwrap().cursor, 0);
    assert_eq!(
        store
            .persist_execution(&record, &[event(&record, 2, EventKind::Completed)])
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(store.events(record.id, 0).await.unwrap().is_empty());
    let events = vec![
        event(&record, 1, EventKind::Started),
        event(&record, 2, EventKind::Completed),
    ];
    store.persist_execution(&record, &events).await.unwrap();
    store.persist_execution(&record, &events).await.unwrap();
    assert_eq!(store.execution(record.id).await.unwrap().cursor, 2);
    assert_eq!(store.events(record.id, 1).await.unwrap().len(), 1);
    assert_eq!(
        store
            .persist_execution(&record, &[event(&record, 3, EventKind::Completed)])
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    record.state = ExecutionState::Failed;
    assert_eq!(
        store
            .persist_execution(&record, &[])
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    store.close().await;
}

#[tokio::test]
async fn unknown_is_not_completion_and_worker_progress_preserves_cancellation() {
    let store = Store::memory().await.unwrap();
    let sandbox = running(&store).await;
    let mut record = store
        .create_execution(sandbox.id, &spec(), "command")
        .await
        .unwrap();
    store.cancel_execution(record.id).await.unwrap();
    record.state = ExecutionState::Unknown;
    record.cleanup = CleanupState::Unknown;
    assert_eq!(
        store
            .persist_execution(&record, &[event(&record, 1, EventKind::Completed)])
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidState
    );
    store
        .persist_execution(&record, &[event(&record, 1, EventKind::Diagnostic)])
        .await
        .unwrap();
    let observed = store.execution(record.id).await.unwrap();
    assert!(observed.cancel_requested);
    assert!(!observed.execution.state.is_terminal());
    store
        .finish_execution(
            record.id,
            ExecutionState::Failed,
            "worker confirmed whole-sandbox termination",
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .events(record.id, 0)
            .await
            .unwrap()
            .iter()
            .filter(|event| event.kind == EventKind::Completed)
            .count(),
        1
    );
    store.close().await;
}

#[tokio::test]
async fn sqlite_restart_keeps_identity_requests_results_and_replay_cursor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.db");
    let store = Store::open(&path).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut reopened_store = None;
    let result = AssertUnwindSafe(async {
        let installation = store.installation_id();
        let sandbox = running(&store).await;
        let mut record = store
            .create_execution(sandbox.id, &spec(), "command")
            .await
            .unwrap();
        record.state = ExecutionState::Failed;
        record.exit_code = Some(23);
        record.cleanup = CleanupState::Complete;
        record.finished_at = Some(Utc::now());
        store
            .persist_execution(&record, &[event(&record, 1, EventKind::Completed)])
            .await
            .unwrap();
        store.close().await;
        reopened_store = Some(Store::open(&path).await.unwrap());
        let reopened = reopened_store.as_ref().unwrap();
        assert_eq!(reopened.installation_id(), installation);
        assert_eq!(
            reopened
                .execution(record.id)
                .await
                .unwrap()
                .execution
                .exit_code,
            Some(23)
        );
        assert_eq!(reopened.execution(record.id).await.unwrap().cursor, 1);
        assert_eq!(reopened.events(record.id, 0).await.unwrap().len(), 1);
        reopened.close().await;
    })
    .catch_unwind()
    .await;
    store.close().await;
    if let Some(reopened) = reopened_store {
        reopened.close().await;
    }
    directory.close().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn stale_worker_registration_cannot_advertise_live_capabilities() {
    let store = Store::memory().await.unwrap();
    let mut worker = WorkerRegistration {
        id: Uuid::new_v4(),
        endpoint: "http://127.0.0.1:1234".into(),
        token: "private-test-token".into(),
        heartbeat: Utc::now(),
        profiles: vec![profile()],
    };
    store.register_worker(&worker).await.unwrap();
    assert_eq!(store.worker().await.unwrap().id, worker.id);
    worker.heartbeat = Utc::now() - Duration::seconds(11);
    store.register_worker(&worker).await.unwrap();
    assert_eq!(
        store.worker().await.err().unwrap().code,
        ErrorCode::BackendUnavailable
    );
    store.close().await;
}

#[tokio::test]
async fn opposite_desired_state_waits_for_a_new_worker_observation() {
    let store = Store::memory().await.unwrap();
    let sandbox = running(&store).await;
    let pause = store
        .set_desired(sandbox.id, DesiredState::Paused, "pause")
        .await
        .unwrap();
    let resume = store
        .set_desired(sandbox.id, DesiredState::Running, "resume")
        .await
        .unwrap();
    assert_eq!(resume.state, OperationState::Pending);
    assert_eq!(
        store.operation(pause.id).await.unwrap().state,
        OperationState::Cancelled
    );
    store.close().await;
}
