use chrono::Utc;
use futures_util::FutureExt;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use serde_json::json;
use std::{collections::BTreeSet, future::Future, panic::AssertUnwindSafe};
use uuid::Uuid;

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
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
async fn source(store: &Store) -> Uuid {
    let profile = RuntimeProfile {
        id: "test".into(),
        placement: Placement::Local,
        isolation: Isolation::Gvisor,
        availability: Availability::Available,
        capabilities: BTreeSet::from([Capability::Commands, Capability::NetworkIsolation]),
        max_resources: ResourceLimits::default(),
        max_ttl_seconds: 86400,
        reason: None,
    };
    let created = store
        .create_sandbox(&profile, &CreateSandbox::new("test", "fixture"), "source")
        .await
        .unwrap();
    let mut stored = store.sandbox(created.sandbox.id).await.unwrap();
    stored.sandbox.state = SandboxState::Starting;
    store.observe(stored.clone()).await.unwrap();
    stored.sandbox.state = SandboxState::Running;
    store.observe(stored).await.unwrap();
    created.sandbox.id
}
fn event(
    context: Uuid,
    sequence: u64,
    run: Option<Uuid>,
    kind: CodeContextEventKind,
    data: serde_json::Value,
) -> CodeContextEvent {
    CodeContextEvent {
        sequence,
        context_id: context,
        run_id: run,
        timestamp: Utc::now(),
        kind,
        data,
    }
}
async fn ready(store: &Store, sandbox: Uuid, key: &str) -> CodeContext {
    let mut agent = store
        .create_code_context(sandbox, &CodeContextSpec::default(), key)
        .await
        .unwrap();
    assert!(store.dispatch_code_context(agent.id).await.unwrap());
    assert!(!store.dispatch_code_context(agent.id).await.unwrap());
    agent.sandbox_id = Uuid::nil();
    agent.created_at += chrono::Duration::seconds(2);
    agent.state = CodeContextState::Ready;
    agent.ready_at = Some(Utc::now());
    agent.kernel_info = Some(json!({"protocol_version":"5.3","language_info":{"name":"python"}}));
    store
        .append_code_context_events(
            agent.id,
            &[event(
                agent.id,
                1,
                None,
                CodeContextEventKind::Ready,
                json!(agent),
            )],
        )
        .await
        .unwrap();
    agent
}
async fn started(
    store: &Store,
    context: Uuid,
    key: &str,
    spec: CodeRunSpec,
    sequence: u64,
) -> CodeRun {
    let mut run = store.create_code_run(context, &spec, key).await.unwrap();
    assert!(store.dispatch_code_run(run.id).await.unwrap());
    assert!(!store.dispatch_code_run(run.id).await.unwrap());
    run.created_at += chrono::Duration::seconds(2);
    run.events_after = 0; // The private agent uses its own cursor domain.
    run.state = CodeRunState::Running;
    run.started_at = Some(Utc::now());
    store
        .append_code_context_events(
            context,
            &[event(
                context,
                sequence,
                Some(run.id),
                CodeContextEventKind::RunStarted,
                json!(run),
            )],
        )
        .await
        .unwrap();
    run
}
fn completed(mut run: CodeRun, state: CodeRunState) -> CodeRun {
    run.state = state;
    run.finished_at = Some(Utc::now());
    run.kernel_status = match state {
        CodeRunState::KernelSucceeded => Some("ok".into()),
        CodeRunState::KernelFailed => Some("error".into()),
        _ => None,
    };
    run
}
fn closed(mut agent: CodeContext, state: CodeContextState, cleanup: CleanupState) -> CodeContext {
    agent.state = state;
    agent.cleanup = cleanup;
    agent.finished_at = Some(Utc::now());
    agent.reason = Some("fixture runtime collection observation".into());
    agent
}

#[tokio::test]
async fn identities_dispatch_and_replay_keep_completed_code_immutable_but_allow_late_output() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let spec = CodeContextSpec::default();
        let (a, b) = tokio::join!(
            store.create_code_context(sandbox, &spec, "same"),
            store.create_code_context(sandbox, &spec, "same")
        );
        let context = a.unwrap();
        assert_eq!(b.unwrap().id, context.id);
        let changed = CodeContextSpec {
            cwd: ".".into(),
            ..Default::default()
        };
        assert_eq!(
            store
                .create_code_context(sandbox, &changed, "same")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert!(store.dispatch_code_context(context.id).await.unwrap());
        let mut agent = context.clone();
        agent.sandbox_id = Uuid::nil();
        agent.created_at += chrono::Duration::seconds(2);
        agent.state = CodeContextState::Ready;
        agent.ready_at = Some(Utc::now());
        agent.kernel_info = Some(json!({"language":"python"}));
        let ready = event(
            context.id,
            1,
            None,
            CodeContextEventKind::Ready,
            json!(agent),
        );
        store
            .append_code_context_events(context.id, std::slice::from_ref(&ready))
            .await
            .unwrap();
        assert_eq!(
            store
                .code_context(context.id)
                .await
                .unwrap()
                .context
                .created_at,
            context.created_at
        );
        let spec = CodeRunSpec::new("counter+=1");
        let (a, b) = tokio::join!(
            store.create_code_run(context.id, &spec, "same"),
            store.create_code_run(context.id, &spec, "same")
        );
        let accepted = a.unwrap();
        assert_eq!(b.unwrap().id, accepted.id);
        assert!(store.dispatch_code_run(accepted.id).await.unwrap());
        let mut run = accepted.clone();
        run.created_at += chrono::Duration::seconds(2);
        run.state = CodeRunState::Running;
        run.started_at = Some(Utc::now());
        let begin = event(
            context.id,
            2,
            Some(run.id),
            CodeContextEventKind::RunStarted,
            json!(run),
        );
        let output = event(
            context.id,
            3,
            Some(run.id),
            CodeContextEventKind::Stdout,
            json!({"late":false,"content":{"name":"stdout","text":"42\n"}}),
        );
        let end = event(
            context.id,
            4,
            Some(run.id),
            CodeContextEventKind::RunCompleted,
            json!(completed(run.clone(), CodeRunState::KernelSucceeded)),
        );
        let batch = vec![begin, output.clone(), end];
        store
            .append_code_context_events(context.id, &batch)
            .await
            .unwrap();
        let final_run = store.code_run(run.id).await.unwrap().run;
        assert_eq!(final_run.state, CodeRunState::KernelSucceeded);
        assert_eq!(final_run.created_at, accepted.created_at);
        assert_eq!(final_run.events_after, accepted.events_after);
        assert_eq!(accepted.events_after, 1);
        store
            .append_code_context_events(context.id, &batch)
            .await
            .unwrap();
        let mut tampered = output;
        tampered.data["content"]["text"] = json!("different");
        assert_eq!(
            store
                .append_code_context_events(context.id, &[tampered])
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let late = event(
            context.id,
            5,
            Some(run.id),
            CodeContextEventKind::Stdout,
            json!({"late":true,"content":{"name":"stdout","text":"background"}}),
        );
        store
            .append_code_context_events(context.id, &[late])
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(store.code_run(run.id).await.unwrap().run).unwrap(),
            json!(final_run)
        );
        let events = store.code_context_events(context.id, 0).await.unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == CodeContextEventKind::RunCompleted)
                .count(),
            1
        );
        assert!(store.code_context_events(context.id, 6).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn close_intent_wins_late_kernel_result_and_cancellation_waits_for_collection() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let agent = ready(&store, sandbox, "context").await;
        let active = started(&store, agent.id, "active", CodeRunSpec::new("sleep()"), 2).await;
        let queued = store
            .create_code_run(agent.id, &CodeRunSpec::new("must_not_repeat()"), "queued")
            .await
            .unwrap();
        store.dispatch_code_run(queued.id).await.unwrap();
        store.cancel_code_run(active.id).await.unwrap();
        assert_eq!(
            store
                .code_context(agent.id)
                .await
                .unwrap()
                .context
                .desired_state,
            CodeContextDesiredState::Closed
        );
        assert!(store.code_run(queued.id).await.unwrap().cancel_requested);
        let late = event(
            agent.id,
            3,
            Some(active.id),
            CodeContextEventKind::RunCompleted,
            json!(completed(active.clone(), CodeRunState::KernelSucceeded)),
        );
        let queued_end = event(
            agent.id,
            4,
            Some(queued.id),
            CodeContextEventKind::RunCompleted,
            json!(completed(queued.clone(), CodeRunState::Cancelled)),
        );
        store
            .append_code_context_events(agent.id, &[late.clone(), queued_end.clone()])
            .await
            .unwrap();
        assert!(
            store
                .code_run(active.id)
                .await
                .unwrap()
                .run
                .finished_at
                .is_none()
        );
        assert!(
            store
                .code_run(queued.id)
                .await
                .unwrap()
                .run
                .finished_at
                .is_none()
        );
        assert_eq!(store.code_context(agent.id).await.unwrap().cursor, 4);
        assert_eq!(
            store.code_context_events(agent.id, 0).await.unwrap().len(),
            2
        );
        let final_event = event(
            agent.id,
            5,
            None,
            CodeContextEventKind::Closed,
            json!(closed(
                agent.clone(),
                CodeContextState::Closed,
                CleanupState::Complete
            )),
        );
        store
            .append_code_context_events(agent.id, std::slice::from_ref(&final_event))
            .await
            .unwrap();
        for id in [active.id, queued.id] {
            let run = store.code_run(id).await.unwrap().run;
            assert_eq!(run.state, CodeRunState::Cancelled);
            assert!(run.finished_at.is_some());
            assert!(run.kernel_status.is_none());
            assert_eq!(run.finished_at, Some(final_event.timestamp));
        }
        let public = store.code_context_events(agent.id, 0).await.unwrap();
        assert_eq!(
            public
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            (1..=public.len() as u64).collect::<Vec<_>>()
        );
        assert_eq!(public.last().unwrap().kind, CodeContextEventKind::Closed);
        assert_eq!(
            public
                .iter()
                .filter(|event| event.kind == CodeContextEventKind::RunCompleted)
                .count(),
            2
        );
        assert!(
            public
                .iter()
                .any(|event| event.kind == CodeContextEventKind::Diagnostic
                    && event.data["reported"]["state"] == "kernel_succeeded")
        );
        store
            .append_code_context_events(agent.id, &[late, queued_end, final_event])
            .await
            .unwrap();
        assert!(store.code_run_work(agent.id).await.unwrap().is_empty());
        assert!(store.code_context_work(sandbox).await.unwrap().is_empty());
        assert!(
            store
                .create_code_run(agent.id, &CodeRunSpec::new("new"), "new")
                .await
                .is_err()
        );
    })
    .await;
}

#[tokio::test]
async fn unknown_cleanup_remains_charged_until_runtime_absence_and_does_not_create_success() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let mut contexts = Vec::new();
        for index in 0..4 {
            contexts.push(ready(&store, sandbox, &format!("context-{index}")).await);
        }
        let first = &contexts[0];
        let run = started(
            &store,
            first.id,
            "run",
            CodeRunSpec::new("maybe_executed()"),
            2,
        )
        .await;
        assert_eq!(
            store
                .create_code_context(sandbox, &CodeContextSpec::default(), "retry")
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let end = event(
            first.id,
            3,
            Some(run.id),
            CodeContextEventKind::RunCompleted,
            json!(completed(run.clone(), CodeRunState::Unknown)),
        );
        let unknown = event(
            first.id,
            4,
            None,
            CodeContextEventKind::Closed,
            json!(closed(
                first.clone(),
                CodeContextState::Unknown,
                CleanupState::Unknown
            )),
        );
        store
            .append_code_context_events(first.id, &[end, unknown])
            .await
            .unwrap();
        assert_eq!(
            store.code_context(first.id).await.unwrap().context.cleanup,
            CleanupState::Unknown
        );
        assert_eq!(
            store.code_run(run.id).await.unwrap().run.state,
            CodeRunState::Unknown
        );
        assert!(
            store
                .code_run(run.id)
                .await
                .unwrap()
                .run
                .finished_at
                .is_none()
        );
        assert!(
            !store
                .code_context_events(first.id, 0)
                .await
                .unwrap()
                .iter()
                .any(|event| event.kind == CodeContextEventKind::Closed)
        );
        assert_eq!(
            store
                .create_code_context(sandbox, &CodeContextSpec::default(), "retry")
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        store
            .finish_code_context_absent(first.id, "fixture confirmed whole-runtime absence")
            .await
            .unwrap();
        let value = store.code_run(run.id).await.unwrap().run;
        assert_eq!(value.state, CodeRunState::Unknown);
        assert!(value.finished_at.is_some());
        assert!(value.kernel_status.is_none());
        assert!(store.code_run_work(first.id).await.unwrap().is_empty());
        let next = store
            .create_code_context(sandbox, &CodeContextSpec::default(), "retry")
            .await
            .unwrap();
        assert_ne!(next.id, first.id);
        assert!(store.code_context(first.id).await.unwrap().ever_ready);
        assert!(!store.dispatch_code_context(first.id).await.unwrap());
    })
    .await;
}

#[tokio::test]
async fn event_identity_gaps_budgets_and_multi_event_failures_roll_back_atomically() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let agent = ready(&store, sandbox, "context").await;
        let mut spec = CodeRunSpec::new("print(42)");
        spec.max_output_bytes = 512;
        let run = started(&store, agent.id, "run", spec, 2).await;
        let small = event(
            agent.id,
            3,
            Some(run.id),
            CodeContextEventKind::Stdout,
            json!({"late":false,"content":{"text":"42"}}),
        );
        let too_big = event(
            agent.id,
            4,
            Some(run.id),
            CodeContextEventKind::Stdout,
            json!({"late":false,"content":{"text":"x".repeat(1024)}}),
        );
        assert!(
            store
                .append_code_context_events(agent.id, &[small.clone(), too_big])
                .await
                .is_err()
        );
        assert_eq!(store.code_context(agent.id).await.unwrap().cursor, 2);
        assert_eq!(
            store.code_context_events(agent.id, 0).await.unwrap().len(),
            2
        );
        let mut gap = small.clone();
        gap.sequence = 4;
        assert!(
            store
                .append_code_context_events(agent.id, &[gap])
                .await
                .is_err()
        );
        let mut wrong = small.clone();
        wrong.run_id = Some(Uuid::new_v4());
        assert!(
            store
                .append_code_context_events(agent.id, &[wrong])
                .await
                .is_err()
        );
        let mut other = small.clone();
        other.context_id = Uuid::new_v4();
        assert!(
            store
                .append_code_context_events(agent.id, &[other])
                .await
                .is_err()
        );
        store
            .append_code_context_events(agent.id, &[small])
            .await
            .unwrap();
        let mut wrong = completed(run.clone(), CodeRunState::KernelFailed);
        wrong.kernel_status = Some("ok".into());
        assert!(
            store
                .append_code_context_events(
                    agent.id,
                    &[event(
                        agent.id,
                        4,
                        Some(run.id),
                        CodeContextEventKind::RunCompleted,
                        json!(wrong)
                    )]
                )
                .await
                .is_err()
        );
        let end = event(
            agent.id,
            4,
            Some(run.id),
            CodeContextEventKind::RunCompleted,
            json!(completed(run.clone(), CodeRunState::KernelFailed)),
        );
        store
            .append_code_context_events(agent.id, &[end])
            .await
            .unwrap();
        assert_eq!(
            store.code_run(run.id).await.unwrap().run.state,
            CodeRunState::KernelFailed
        );
        let extra = event(
            agent.id,
            5,
            Some(run.id),
            CodeContextEventKind::RunCompleted,
            json!(completed(run, CodeRunState::KernelSucceeded)),
        );
        assert!(
            store
                .append_code_context_events(agent.id, &[extra])
                .await
                .is_err()
        );
        assert_eq!(store.code_context(agent.id).await.unwrap().cursor, 4);
    })
    .await;
}

#[tokio::test]
async fn queue_reservation_rollback_and_close_of_undispatched_work() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let context = store
            .create_code_context(sandbox, &CodeContextSpec::default(), "context")
            .await
            .unwrap();
        let spec = CodeRunSpec::new("one()");
        assert!(
            store
                .create_code_run(context.id, &spec, "retry")
                .await
                .is_err()
        );
        store.dispatch_code_context(context.id).await.unwrap();
        let mut agent = context.clone();
        agent.state = CodeContextState::Ready;
        agent.ready_at = Some(Utc::now());
        agent.kernel_info = Some(json!({"language":"python"}));
        store
            .append_code_context_events(
                context.id,
                &[event(
                    context.id,
                    1,
                    None,
                    CodeContextEventKind::Ready,
                    json!(agent),
                )],
            )
            .await
            .unwrap();
        let mut runs = Vec::new();
        for index in 0..8 {
            runs.push(
                store
                    .create_code_run(context.id, &spec, &format!("run-{index}"))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            store
                .create_code_run(context.id, &spec, "retry")
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let mut first = runs[0].clone();
        store.dispatch_code_run(first.id).await.unwrap();
        first.state = CodeRunState::Running;
        first.started_at = Some(Utc::now());
        store
            .append_code_context_events(
                context.id,
                &[event(
                    context.id,
                    2,
                    Some(first.id),
                    CodeContextEventKind::RunStarted,
                    json!(first),
                )],
            )
            .await
            .unwrap();
        let extra = store
            .create_code_run(context.id, &spec, "retry")
            .await
            .unwrap();
        assert!(!runs.iter().any(|run| run.id == extra.id));
        store.close_code_context(context.id, "close").await.unwrap();
        assert!(store.dispatch_code_run(extra.id).await.is_err());
        store
            .finish_code_context_absent(context.id, "fixture runtime absence")
            .await
            .unwrap();
        for run in runs.iter().skip(1).chain(std::iter::once(&extra)) {
            assert_eq!(
                store.code_run(run.id).await.unwrap().run.state,
                CodeRunState::Cancelled
            );
        }
        assert_eq!(
            store.code_run(first.id).await.unwrap().run.state,
            CodeRunState::Cancelled
        );
    })
    .await;
}

#[tokio::test]
async fn runtime_loss_is_not_cancellation_and_source_expiry_can_confirm_timeout() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let lost = ready(&store, sandbox, "lost").await;
        let active = started(&store, lost.id, "active", CodeRunSpec::new("maybe()"), 2).await;
        let queued = store
            .create_code_run(lost.id, &CodeRunSpec::new("not_sent()"), "queued")
            .await
            .unwrap();
        store.cancel_code_run(active.id).await.unwrap();
        store
            .finish_code_context_absent_with_state(
                lost.id,
                "fixture observed runtime exit",
                CodeRunState::Unknown,
            )
            .await
            .unwrap();
        assert_eq!(
            store.code_context(lost.id).await.unwrap().context.state,
            CodeContextState::Failed
        );
        assert_eq!(
            store.code_run(active.id).await.unwrap().run.state,
            CodeRunState::Unknown
        );
        assert_eq!(
            store.code_run(queued.id).await.unwrap().run.state,
            CodeRunState::Cancelled
        );
        let expired = ready(&store, sandbox, "expired").await;
        let run = started(&store, expired.id, "run", CodeRunSpec::new("work()"), 2).await;
        assert!(
            store
                .finish_code_context_absent_with_state(
                    expired.id,
                    "invalid",
                    CodeRunState::KernelSucceeded
                )
                .await
                .is_err()
        );
        assert_eq!(
            store
                .code_context(expired.id)
                .await
                .unwrap()
                .context
                .cleanup,
            CleanupState::Pending
        );
        store
            .close_code_context(expired.id, "source-expiry")
            .await
            .unwrap();
        store
            .finish_code_context_absent_with_state(
                expired.id,
                "fixture confirmed expired runtime absence",
                CodeRunState::TimedOut,
            )
            .await
            .unwrap();
        let result = store.code_run(run.id).await.unwrap().run;
        assert_eq!(result.state, CodeRunState::TimedOut);
        assert!(result.kernel_status.is_none() && result.finished_at.is_some());
        assert_eq!(result.events_after, 1);
    })
    .await;
}

#[tokio::test]
async fn schema_three_migration_and_reopen_preserve_sessions_artifacts_and_ambiguous_dispatch() {
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
        let session = store
            .create_session(sandbox, &SessionSpec::shell(), "session")
            .await
            .unwrap();
        store
            .enqueue_session_control(
                session.execution.id,
                &SessionControl {
                    sequence: 1,
                    action: SessionAction::CloseInput,
                },
            )
            .await
            .unwrap();
        let artifact = store
            .create_artifact(sandbox, &CreateArtifact::new("old.bin"), "artifact")
            .await
            .unwrap();
        (
            store.installation_id(),
            sandbox,
            session.execution.id,
            artifact.artifact.id,
            artifact.operation.id,
        )
    })
    .catch_unwind()
    .await;
    store.close().await;
    drop(store);
    let result=AssertUnwindSafe(async {
        let (installation,sandbox,session,artifact,operation)=setup.unwrap();
        let mut connection=SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&db_path)).await.unwrap();
        let downgrading=sqlx::raw_sql("DROP TABLE sandbox_scopes;DROP TABLE code_context_events;DROP TABLE code_context_sources;DROP TABLE code_runs;DROP TABLE code_contexts;UPDATE meta SET value='3' WHERE key='schema_version'").execute(&mut connection).await;
        connection.close().await.unwrap();downgrading.unwrap();
        let migrated=Store::open(&db_path).await.unwrap();
        let work=AssertUnwindSafe(async {
            assert_eq!(migrated.installation_id(),installation);assert_eq!(migrated.session_control(session,1).await.unwrap().receipt.state,SessionControlState::Pending);
            assert_eq!(migrated.artifact(artifact).await.unwrap().artifact.source_path,"old.bin");assert_eq!(migrated.operation(operation).await.unwrap().resource_id,artifact);
            let context=ready(&migrated,sandbox,"context").await;let run=migrated.create_code_run(context.id,&CodeRunSpec::new("must-not-repeat()"),"run").await.unwrap();
            assert!(migrated.dispatch_code_run(run.id).await.unwrap());migrated.cancel_code_run(run.id).await.unwrap();(context.id,run.id)
        }).catch_unwind().await;
        migrated.close().await;drop(migrated);let (context,run)=work.unwrap();
        let reopened=Store::open(&db_path).await.unwrap();
        let checking=AssertUnwindSafe(async {
            assert_eq!(reopened.installation_id(),installation);let stored=reopened.code_context(context).await.unwrap();assert!(stored.dispatched && stored.ever_ready);assert_eq!(stored.cursor,1);
            assert_eq!(stored.context.desired_state,CodeContextDesiredState::Closed);let pending=reopened.code_run(run).await.unwrap();assert!(pending.dispatched && pending.cancel_requested);assert!(pending.run.finished_at.is_none());
            assert!(!reopened.dispatch_code_run(run).await.unwrap());reopened.finish_code_context_absent(context,"fixture actual runtime absence").await.unwrap();
            assert_eq!(reopened.code_run(run).await.unwrap().run.state,CodeRunState::Cancelled);assert_eq!(reopened.code_context_events(context,0).await.unwrap().last().unwrap().kind,CodeContextEventKind::Closed);
        }).catch_unwind().await;
        reopened.close().await;drop(reopened);checking.unwrap();
    }).catch_unwind().await;
    dir.close().unwrap();
    assert!(!path.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn definitive_rejection_preserves_fifo_and_collected_parent_does_not_hide_child_work() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let context = ready(&store, sandbox, "context").await;
        let mut ids = Vec::new();
        for index in 0..4 {
            ids.push(
                store
                    .create_code_run(
                        context.id,
                        &CodeRunSpec::new(format!("{index}")),
                        &format!("run-{index}"),
                    )
                    .await
                    .unwrap()
                    .id,
            );
        }
        assert_eq!(
            store
                .code_run_work(context.id)
                .await
                .unwrap()
                .iter()
                .map(|run| run.run.id)
                .collect::<Vec<_>>(),
            ids
        );
        store.dispatch_code_run(ids[0]).await.unwrap();
        let refusal = ApiError::new(ErrorCode::QuotaExceeded, "native queue is full");
        store.reject_code_run(ids[0], &refusal).await.unwrap();
        store.reject_code_run(ids[0], &refusal).await.unwrap();
        let rejected = store.code_run(ids[0]).await.unwrap().run;
        assert_eq!(rejected.state, CodeRunState::Rejected);
        assert!(rejected.started_at.is_none() && rejected.kernel_status.is_none());
        assert_eq!(rejected.events_after, 1);
        let snapshot = store.code_context(context.id).await.unwrap();
        assert_eq!((snapshot.cursor, snapshot.events_cursor), (1, 2));
        let run = started(
            &store,
            context.id,
            "observed",
            CodeRunSpec::new("observed()"),
            2,
        )
        .await;
        assert!(store.reject_code_run(run.id, &refusal).await.is_err());
        store
            .set_desired(sandbox, DesiredState::Terminated, "terminate")
            .await
            .unwrap();
        let mut parent = store.sandbox(sandbox).await.unwrap();
        parent.sandbox.state = SandboxState::Stopping;
        store.observe(parent.clone()).await.unwrap();
        parent.sandbox.state = SandboxState::Terminated;
        parent.sandbox.cleanup = CleanupState::Complete;
        store.observe(parent).await.unwrap();
        assert_eq!(store.work().await.unwrap().len(), 1);
        store
            .close_code_context(context.id, "parent-absent")
            .await
            .unwrap();
        store
            .finish_code_context_absent_with_state(
                context.id,
                "fixture observed whole runtime absence",
                CodeRunState::Cancelled,
            )
            .await
            .unwrap();
        assert!(store.work().await.unwrap().is_empty());
        assert_eq!(
            store.code_run(ids[0]).await.unwrap().run.state,
            CodeRunState::Rejected
        );
    })
    .await;
}

#[tokio::test]
async fn rich_history_batches_are_byte_bounded_and_resume_without_gaps() {
    checked(|store| async move {
        let sandbox = source(&store).await;
        let context = ready(&store, sandbox, "context").await;
        let mut next = 2;
        for index in 0..2 {
            let mut spec = CodeRunSpec::new("rich_output()");
            spec.max_output_bytes = 16 * 1024 * 1024;
            let run = started(&store, context.id, &format!("run-{index}"), spec, next).await;
            next += 1;
            let mut events = Vec::new();
            for _ in 0..10 {
                events.push(event(
                    context.id,
                    next,
                    Some(run.id),
                    CodeContextEventKind::Stdout,
                    json!({"late":false,"content":{"text":"x".repeat(1024*1024)}}),
                ));
                next += 1;
            }
            events.push(event(
                context.id,
                next,
                Some(run.id),
                CodeContextEventKind::RunCompleted,
                json!(completed(run, CodeRunState::KernelSucceeded)),
            ));
            next += 1;
            store
                .append_code_context_events(context.id, &events)
                .await
                .unwrap();
        }
        let first = store.code_context_events(context.id, 0).await.unwrap();
        let cursor = first.last().unwrap().sequence;
        assert!(cursor < next - 1);
        assert!(
            first
                .iter()
                .map(|event| serde_json::to_vec(event).unwrap().len())
                .sum::<usize>()
                <= 16 * 1024 * 1024
        );
        let second = store.code_context_events(context.id, cursor).await.unwrap();
        assert_eq!(second.last().unwrap().sequence, next - 1);
        assert_eq!(
            first
                .iter()
                .chain(second.iter())
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            (1..next).collect::<Vec<_>>()
        );
    })
    .await;
}
