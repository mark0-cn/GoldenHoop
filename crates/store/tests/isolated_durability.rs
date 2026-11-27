use futures_util::FutureExt;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use std::{collections::BTreeSet, future::Future, panic::AssertUnwindSafe, path::PathBuf};
use uuid::Uuid;

#[tokio::test]
async fn completed_cleanup_with_pending_termination_is_reconciled_after_restart() {
    checked(|store, path| async move {
        let id = root(&store, None, 300).await;
        let operation = store
            .set_desired(id, DesiredState::Terminated, "close-before-loss")
            .await
            .unwrap();
        assert_eq!(operation.state, OperationState::Pending);
        let mut observed = store.sandbox(id).await.unwrap();
        observed.sandbox.state = SandboxState::Failed;
        observed.sandbox.cleanup = CleanupState::Complete;
        observed.handle = None;
        // Synthetic native absence models the durable boundary before the
        // worker's separate finish_operations call. No backend is exercised.
        store.observe(observed).await.unwrap();
        store.close().await;

        let reopened = Store::open(&path).await.unwrap();
        let result = AssertUnwindSafe(async {
            assert_eq!(
                reopened.operation(operation.id).await.unwrap().state,
                OperationState::Pending
            );
            assert_eq!(
                reopened
                    .set_desired(id, DesiredState::Terminated, "repeat-close-after-restart")
                    .await
                    .unwrap()
                    .id,
                operation.id
            );
            let pending = reopened.work().await.unwrap();
            let recovered = pending
                .iter()
                .find(|stored| stored.sandbox.id == id)
                .expect("pending lifecycle acknowledgement must remain reconciliation work");
            assert_eq!(recovered.sandbox.state, SandboxState::Failed);
            assert_eq!(recovered.sandbox.cleanup, CleanupState::Complete);
            assert_eq!(recovered.sandbox.desired_state, DesiredState::Terminated);
            assert!(recovered.handle.is_none());
            reopened
                .finish_operations(id, "terminate", OperationState::Succeeded, None)
                .await
                .unwrap();
            let finished = reopened.operation(operation.id).await.unwrap();
            assert_eq!(finished.state, OperationState::Succeeded);
            assert!(finished.finished_at.is_some());
            assert!(reopened.work().await.unwrap().is_empty());
        })
        .catch_unwind()
        .await;
        reopened.close().await;
        drop(reopened);
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    })
    .await;
}

async fn checked<F, Fut>(test: F)
where
    F: FnOnce(Store, PathBuf) -> Fut,
    Fut: Future<Output = ()>,
{
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.db");
    let store = Store::open(&path).await.unwrap();
    let result = AssertUnwindSafe(test(store.clone(), path))
        .catch_unwind()
        .await;
    store.close().await;
    drop(store);
    let root = dir.path().to_owned();
    dir.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
fn profile() -> RuntimeProfile {
    RuntimeProfile {
        id: "test".into(),
        placement: Placement::Local,
        isolation: Isolation::Gvisor,
        availability: Availability::Available,
        capabilities: BTreeSet::from([
            Capability::Commands,
            Capability::Files,
            Capability::ShellSessions,
            Capability::Pty,
            Capability::CodeContexts,
            Capability::Artifacts,
            Capability::Diagnostics,
            Capability::Pause,
            Capability::NetworkIsolation,
            Capability::IsolatedSessions,
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
fn limits(cpu: u32, mib: u64, pids: u32) -> ResourceLimits {
    ResourceLimits {
        cpu_millis: cpu,
        memory_bytes: mib * 1024 * 1024,
        pids,
    }
}
async fn running(store: &Store, id: Uuid) {
    let mut stored = store.sandbox(id).await.unwrap();
    stored.sandbox.state = SandboxState::Starting;
    store.observe(stored.clone()).await.unwrap();
    stored.sandbox.state = SandboxState::Running;
    store.observe(stored).await.unwrap();
}
async fn root(store: &Store, budget: Option<ResourceLimits>, ttl: u64) -> Uuid {
    let mut request = CreateSandbox::new("test", "fixture");
    request.resources = limits(1000, 512, 128);
    request.child_budget = budget;
    request.ttl_seconds = ttl;
    let id = store
        .create_sandbox(&profile(), &request, &Uuid::new_v4().to_string())
        .await
        .unwrap()
        .sandbox
        .id;
    running(store, id).await;
    id
}
async fn collect(store: &Store, id: Uuid) {
    store
        .set_desired(id, DesiredState::Terminated, &format!("collect-{id}"))
        .await
        .unwrap();
    let mut record = store.sandbox(id).await.unwrap();
    if record.sandbox.state != SandboxState::Failed {
        record.sandbox.state = SandboxState::Stopping;
        store.observe(record.clone()).await.unwrap();
        record.sandbox.state = SandboxState::Terminated;
    }
    record.sandbox.cleanup = CleanupState::Complete;
    store.observe(record).await.unwrap();
}

async fn ready_context(store: &Store, sandbox: Uuid) -> CodeContext {
    let mut context = store
        .create_code_context(sandbox, &CodeContextSpec::default(), "ready")
        .await
        .unwrap();
    assert!(store.dispatch_code_context(context.id).await.unwrap());
    context.state = CodeContextState::Ready;
    context.ready_at = Some(chrono::Utc::now());
    context.kernel_info =
        Some(serde_json::json!({"protocol_version":"5.3","language_info":{"name":"python"}}));
    store
        .append_code_context_events(
            context.id,
            &[CodeContextEvent {
                context_id: context.id,
                run_id: None,
                sequence: 1,
                timestamp: chrono::Utc::now(),
                kind: CodeContextEventKind::Ready,
                data: serde_json::to_value(&context).unwrap(),
            }],
        )
        .await
        .unwrap();
    context
}

#[tokio::test]
async fn immutable_feature_ceilings_fence_every_new_work_entry_point() {
    checked(|store, _| async move {
        let parent = root(&store, Some(limits(1000, 512, 128)), 300).await;
        let spec = CreateIsolatedSession {
            resources: limits(100, 64, 16),
            feature_limit: Some(BTreeSet::new()),
            ..Default::default()
        };
        let child = store
            .create_isolated_session(&profile(), parent, &spec, "denied")
            .await
            .unwrap()
            .sandbox
            .id;
        running(&store, child).await;
        assert_eq!(
            store
                .create_execution(child, &CommandSpec::new(["true"]), "cmd")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            store
                .create_session(child, &SessionSpec::shell(), "shell")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            store
                .create_code_context(child, &CodeContextSpec::default(), "ctx")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            store
                .create_artifact(
                    child,
                    &CreateArtifact {
                        path: "file".into(),
                        name: "file".into()
                    },
                    "artifact"
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        for feature in [
            Capability::Files,
            Capability::Diagnostics,
            Capability::Artifacts,
            Capability::CodeContexts,
        ] {
            assert_eq!(
                store
                    .authorize_feature(child, feature)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::Forbidden
            );
        }
        assert_eq!(
            store
                .set_desired(child, DesiredState::Paused, "pause")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            store
                .create_isolated_session(
                    &profile(),
                    child,
                    &CreateIsolatedSession::default(),
                    "grandchild"
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        let shell = store
            .create_isolated_session(
                &profile(),
                parent,
                &CreateIsolatedSession {
                    resources: limits(100, 64, 16),
                    feature_limit: Some(BTreeSet::from([Capability::ShellSessions])),
                    ..Default::default()
                },
                "shell-only",
            )
            .await
            .unwrap()
            .sandbox
            .id;
        running(&store, shell).await;
        store
            .create_session(shell, &SessionSpec::shell(), "pipe")
            .await
            .unwrap();
        let mut pty = SessionSpec::shell();
        pty.terminal = Some(TerminalSize {
            rows: 24,
            columns: 80,
        });
        assert_eq!(
            store
                .create_session(shell, &pty, "pty")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            store
                .create_execution(shell, &CommandSpec::new(["true"]), "cmd")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        collect(&store, child).await;
        collect(&store, shell).await;
        collect(&store, parent).await;
    })
    .await;
}

#[tokio::test]
async fn ancestor_pause_fences_acceptance_and_dispatch_but_preserves_replay_and_close() {
    checked(|store, _| async move {
        let parent = root(&store, Some(limits(1000, 512, 128)), 300).await;
        let child = store
            .create_isolated_session(
                &profile(),
                parent,
                &CreateIsolatedSession {
                    resources: limits(100, 64, 16),
                    ..Default::default()
                },
                "child",
            )
            .await
            .unwrap()
            .sandbox
            .id;
        running(&store, child).await;
        let command = CommandSpec::new(["true"]);
        let execution = store
            .create_execution(child, &command, "old")
            .await
            .unwrap();
        let session = store
            .create_session(child, &SessionSpec::shell(), "old")
            .await
            .unwrap();
        let control = SessionControl {
            sequence: 1,
            action: SessionAction::CloseInput,
        };
        store
            .enqueue_session_control(session.execution.id, &control)
            .await
            .unwrap();
        let context = ready_context(&store, child).await;
        let run_spec = CodeRunSpec::new("42");
        let run = store
            .create_code_run(context.id, &run_spec, "old")
            .await
            .unwrap();
        let pending = store
            .create_code_context(child, &CodeContextSpec::default(), "pending")
            .await
            .unwrap();
        let artifact_spec = CreateArtifact {
            path: "file".into(),
            name: "file".into(),
        };
        let artifact = store
            .create_artifact(child, &artifact_spec, "old")
            .await
            .unwrap();
        store
            .set_desired(parent, DesiredState::Paused, "pause")
            .await
            .unwrap();
        assert_eq!(
            store.sandbox(child).await.unwrap().sandbox.desired_state,
            DesiredState::Running
        );
        assert_eq!(
            store
                .authorize_work(child, Capability::Files)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store
                .create_execution(child, &command, "new")
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store
                .create_session(child, &SessionSpec::shell(), "new")
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store
                .enqueue_session_control(
                    session.execution.id,
                    &SessionControl {
                        sequence: 2,
                        action: SessionAction::CloseInput
                    }
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store
                .create_code_context(child, &CodeContextSpec::default(), "new")
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store
                .dispatch_code_context(pending.id)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store
                .create_code_run(context.id, &run_spec, "new")
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store.dispatch_code_run(run.id).await.unwrap_err().code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store
                .create_artifact(child, &artifact_spec, "new")
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        assert_eq!(
            store
                .create_execution(child, &command, "old")
                .await
                .unwrap()
                .id,
            execution.id
        );
        assert_eq!(
            store
                .create_session(child, &SessionSpec::shell(), "old")
                .await
                .unwrap()
                .execution
                .id,
            session.execution.id
        );
        store
            .enqueue_session_control(session.execution.id, &control)
            .await
            .unwrap();
        assert_eq!(
            store
                .create_code_run(context.id, &run_spec, "old")
                .await
                .unwrap()
                .id,
            run.id
        );
        assert_eq!(
            store
                .create_artifact(child, &artifact_spec, "old")
                .await
                .unwrap()
                .artifact
                .id,
            artifact.artifact.id
        );
        store
            .authorize_feature(child, Capability::Diagnostics)
            .await
            .unwrap();
        store
            .set_desired(parent, DesiredState::Running, "resume")
            .await
            .unwrap();
        store
            .authorize_work(child, Capability::Files)
            .await
            .unwrap();
        assert!(store.dispatch_code_context(pending.id).await.unwrap());
        assert!(store.dispatch_code_run(run.id).await.unwrap());
        store.cancel_execution(execution.id).await.unwrap();
        store.cancel_code_run(run.id).await.unwrap();
        store.close_code_context(context.id, "close").await.unwrap();
        collect(&store, child).await;
        collect(&store, parent).await;
    })
    .await;
}

#[tokio::test]
async fn pause_acknowledgement_waits_for_descendants_and_observed_failure_closes_them_atomically() {
    checked(|store, _| async move {
        let parent = root(&store, Some(limits(1000, 512, 128)), 300).await;
        let child = store
            .create_isolated_session(
                &profile(),
                parent,
                &CreateIsolatedSession {
                    resources: limits(100, 64, 16),
                    ..Default::default()
                },
                "child",
            )
            .await
            .unwrap()
            .sandbox
            .id;
        running(&store, child).await;
        assert!(store.subtree_settled(parent).await.unwrap());
        store
            .set_desired(parent, DesiredState::Paused, "pause")
            .await
            .unwrap();
        for state in [SandboxState::Pausing, SandboxState::Paused] {
            let mut record = store.sandbox(parent).await.unwrap();
            record.sandbox.state = state;
            store.observe(record).await.unwrap();
        }
        assert!(!store.subtree_settled(parent).await.unwrap());
        assert_eq!(
            store
                .set_desired(parent, DesiredState::Paused, "pause-again")
                .await
                .unwrap()
                .state,
            OperationState::Pending
        );
        for state in [SandboxState::Pausing, SandboxState::Paused] {
            let mut record = store.sandbox(child).await.unwrap();
            record.sandbox.state = state;
            store.observe(record).await.unwrap();
        }
        assert!(store.subtree_settled(parent).await.unwrap());
        let mut failed = store.sandbox(parent).await.unwrap();
        failed.sandbox.state = SandboxState::Failed;
        failed.sandbox.cleanup = CleanupState::Pending;
        store.observe(failed).await.unwrap();
        assert_eq!(
            store.sandbox(child).await.unwrap().sandbox.desired_state,
            DesiredState::Terminated
        );
        assert_eq!(
            store.effective_desired(child).await.unwrap(),
            DesiredState::Terminated
        );
        assert!(!store.children_collected(parent).await.unwrap());
        assert_eq!(
            store
                .authorize_work(child, Capability::Files)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        collect(&store, child).await;
        assert!(store.children_collected(parent).await.unwrap());
        collect(&store, parent).await;
    })
    .await;
}

#[tokio::test]
async fn concurrent_reservations_replay_and_unknown_collection_keep_the_parent_charge() {
    checked(|store, _| async move {
        let parent = root(&store, Some(limits(1000, 512, 128)), 300).await;
        let spec = CreateIsolatedSession {
            resources: limits(700, 128, 32),
            ..Default::default()
        };
        let p = profile();
        let (first, second) = tokio::join!(
            store.create_isolated_session(&p, parent, &spec, "one"),
            store.create_isolated_session(&p, parent, &spec, "two")
        );
        let (created, key, rolled_back) = match (first, second) {
            (Ok(value), Err(error)) => {
                assert_eq!(error.code, ErrorCode::QuotaExceeded);
                (value, "one", "two")
            }
            (Err(error), Ok(value)) => {
                assert_eq!(error.code, ErrorCode::QuotaExceeded);
                (value, "two", "one")
            }
            other => panic!("allocation race did not serialize: {other:?}"),
        };
        let id = created.sandbox.id;
        assert_eq!(
            store
                .create_isolated_session(&p, parent, &spec, key)
                .await
                .unwrap()
                .sandbox
                .id,
            id
        );
        assert_eq!(
            store
                .sandbox_scope(parent)
                .await
                .unwrap()
                .allocated_to_children,
            spec.resources
        );
        let altered = CreateIsolatedSession {
            image: Some("different".into()),
            ..spec.clone()
        };
        assert_eq!(
            store
                .create_isolated_session(&p, parent, &altered, key)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let mut failed = store.sandbox(id).await.unwrap();
        failed.sandbox.state = SandboxState::Failed;
        failed.sandbox.cleanup = CleanupState::Unknown;
        store.observe(failed).await.unwrap();
        assert_eq!(
            store
                .create_isolated_session(&p, parent, &spec, rolled_back)
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        collect(&store, id).await;
        assert_eq!(
            store
                .sandbox_scope(parent)
                .await
                .unwrap()
                .allocated_to_children,
            limits(0, 0, 0)
        );
        let retry = store
            .create_isolated_session(&p, parent, &spec, rolled_back)
            .await
            .unwrap();
        assert_ne!(retry.sandbox.id, id);
        assert_eq!(retry.scope.parent_id, Some(parent));
        assert_eq!(retry.scope.root_id, parent);
        assert_eq!(retry.scope.depth, 1);
        assert_eq!(
            store
                .isolated_sessions(parent, None, 1)
                .await
                .unwrap()
                .items
                .len(),
            1
        );
    })
    .await;
}

#[tokio::test]
async fn root_envelopes_are_charged_once_and_parent_collection_waits_for_children() {
    checked(|store, _| async move {
        let parent = root(&store, Some(limits(1000, 512, 128)), 300).await;
        let spec = CreateIsolatedSession {
            resources: limits(1000, 512, 128),
            ..Default::default()
        };
        let child = store
            .create_isolated_session(&profile(), parent, &spec, "child")
            .await
            .unwrap()
            .sandbox
            .id;
        let scope = store.sandbox_scope(parent).await.unwrap();
        assert_eq!(scope.envelope, limits(2000, 1024, 256));
        assert_eq!(
            store.sandbox(parent).await.unwrap().sandbox.resources,
            limits(1000, 512, 128)
        );
        let mut other = CreateSandbox::new("test", "fixture");
        other.resources = limits(14000, 512, 128);
        store
            .create_sandbox(&profile(), &other, "other")
            .await
            .unwrap();
        assert_eq!(
            store
                .create_sandbox(
                    &profile(),
                    &CreateSandbox::new("test", "fixture"),
                    "too-much"
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        store
            .set_desired(parent, DesiredState::Terminated, "terminate-tree")
            .await
            .unwrap();
        assert_eq!(
            store.sandbox(child).await.unwrap().sandbox.desired_state,
            DesiredState::Terminated
        );
        let mut record = store.sandbox(parent).await.unwrap();
        record.sandbox.state = SandboxState::Stopping;
        store.observe(record.clone()).await.unwrap();
        record.sandbox.state = SandboxState::Terminated;
        record.sandbox.cleanup = CleanupState::Complete;
        assert_eq!(
            store.observe(record.clone()).await.unwrap_err().code,
            ErrorCode::InvalidState
        );
        collect(&store, child).await;
        store.observe(record).await.unwrap();
        store
            .create_sandbox(
                &profile(),
                &CreateSandbox::new("test", "fixture"),
                "too-much",
            )
            .await
            .unwrap();
    })
    .await;
}

#[tokio::test]
async fn inheritance_refuses_broader_profile_features_and_network_before_allocation() {
    checked(|store, _| async move {
        let parent = root(&store, Some(limits(4000, 2048, 512)), 300).await;
        let mut spec = CreateIsolatedSession {
            resources: limits(100, 64, 16),
            ..Default::default()
        };
        let mut different = profile();
        different.id = "weaker".into();
        different.isolation = Isolation::Oci;
        assert_eq!(
            store
                .create_isolated_session(&different, parent, &spec, "profile")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        spec.feature_limit = Some(BTreeSet::from([Capability::Gpu]));
        assert_eq!(
            store
                .create_isolated_session(&profile(), parent, &spec, "features")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        spec.feature_limit = None;
        spec.network = Some(NetworkPolicy {
            default_action: NetworkAction::Allow,
            rules: Vec::new(),
        });
        assert_eq!(
            store
                .create_isolated_session(&profile(), parent, &spec, "network")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            store
                .sandbox_scope(parent)
                .await
                .unwrap()
                .allocated_to_children,
            limits(0, 0, 0)
        );
        spec.network = None;
        spec.feature_limit = Some(BTreeSet::from([Capability::Commands]));
        let child = store
            .create_isolated_session(&profile(), parent, &spec, "narrow")
            .await
            .unwrap();
        assert_eq!(
            child.scope.feature_limit,
            Some(BTreeSet::from([Capability::Commands]))
        );
        assert_eq!(child.sandbox.image, "fixture");
        assert_eq!(child.sandbox.profile, "test");
        let no_budget = root(&store, None, 300).await;
        assert_eq!(
            store
                .create_isolated_session(&profile(), no_budget, &spec, "no-budget")
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
    })
    .await;
}

#[tokio::test]
async fn hierarchy_clamps_deadlines_preserves_own_pause_and_closes_all_descendants() {
    use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};

    checked(|store, path| async move {
        let parent = root(&store, Some(limits(1000, 1024, 256)), 300).await;
        let parent_expiry = store.sandbox(parent).await.unwrap().sandbox.expires_at;
        let mut ids = vec![parent];
        for depth in 1..=4 {
            let spec = CreateIsolatedSession {
                resources: limits(100, 64, 16),
                child_budget: if depth < 4 {
                    Some(limits(
                        (5 - depth) * 100,
                        (5 - u64::from(depth)) * 128,
                        (5 - depth) * 32,
                    ))
                } else {
                    None
                },
                ttl_seconds: Some(86400),
                ..Default::default()
            };
            let child = store
                .create_isolated_session(
                    &profile(),
                    *ids.last().unwrap(),
                    &spec,
                    &format!("depth-{depth}"),
                )
                .await
                .unwrap();
            assert_eq!(child.scope.depth, u8::try_from(depth).unwrap());
            assert_eq!(child.scope.root_id, parent);
            assert!(child.sandbox.expires_at <= parent_expiry);
            running(&store, child.sandbox.id).await;
            ids.push(child.sandbox.id);
        }
        let leaf = *ids.last().unwrap();
        assert_eq!(
            store
                .create_isolated_session(
                    &profile(),
                    leaf,
                    &CreateIsolatedSession::default(),
                    "too-deep"
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        store
            .set_desired(ids[2], DesiredState::Paused, "own-pause")
            .await
            .unwrap();
        store
            .set_desired(parent, DesiredState::Paused, "tree-pause")
            .await
            .unwrap();
        assert_eq!(
            store.effective_desired(leaf).await.unwrap(),
            DesiredState::Paused
        );
        store
            .set_desired(parent, DesiredState::Running, "tree-resume")
            .await
            .unwrap();
        assert_eq!(
            store.effective_desired(leaf).await.unwrap(),
            DesiredState::Paused
        );
        store
            .set_desired(ids[2], DesiredState::Running, "own-resume")
            .await
            .unwrap();
        assert_eq!(
            store.effective_desired(leaf).await.unwrap(),
            DesiredState::Running
        );
        store
            .set_desired(parent, DesiredState::Terminated, "tree-close")
            .await
            .unwrap();
        for id in ids {
            assert_eq!(
                store.sandbox(id).await.unwrap().sandbox.desired_state,
                DesiredState::Terminated
            );
            assert_eq!(
                store.effective_desired(id).await.unwrap(),
                DesiredState::Terminated
            );
        }
        let expiring = root(&store, Some(limits(100, 64, 16)), 300).await;
        let spec = CreateIsolatedSession {
            resources: limits(100, 64, 16),
            ttl_seconds: Some(300),
            ..Default::default()
        };
        let child = store
            .create_isolated_session(&profile(), expiring, &spec, "expiring")
            .await
            .unwrap()
            .sandbox
            .id;
        running(&store, child).await;
        let mut snapshots = [
            store.sandbox(expiring).await.unwrap().sandbox,
            store.sandbox(child).await.unwrap().sandbox,
        ];
        assert!(snapshots[1].expires_at <= snapshots[0].expires_at);
        // Supply expired fixture snapshots after setup, preserving their time
        // ordering and clamped deadlines. Native wall-clock expiry has its own
        // runtime gate; filesystem latency must not expire this test's setup.
        let shift = chrono::Utc::now() - chrono::Duration::seconds(1) - snapshots[0].expires_at;
        let mut updates = Vec::new();
        for snapshot in &mut snapshots {
            snapshot.created_at += shift;
            snapshot.expires_at += shift;
            if let Some(observed) = snapshot.observed_at.as_mut() {
                *observed += shift;
            }
            updates.push((
                snapshot.id.to_string(),
                serde_json::to_string(snapshot).unwrap(),
            ));
        }
        let mut connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path))
                .await
                .unwrap();
        let updated = async {
            let mut tx = connection.begin().await?;
            for (id, payload) in updates {
                let result = sqlx::query("UPDATE sandboxes SET payload=? WHERE id=?")
                    .bind(payload)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                if result.rows_affected() != 1 {
                    return Err(sqlx::Error::RowNotFound);
                }
            }
            tx.commit().await
        }
        .await;
        connection.close().await.unwrap();
        updated.unwrap();
        assert_eq!(
            store.effective_desired(child).await.unwrap(),
            DesiredState::Terminated
        );
    })
    .await;
}

#[tokio::test]
async fn live_and_historical_child_limits_are_independent_of_released_resources() {
    checked(|store, _| async move {
        let parent = root(&store, Some(limits(4000, 4096, 1024)), 300).await;
        let spec = CreateIsolatedSession {
            resources: limits(100, 64, 16),
            ..Default::default()
        };
        let mut ids = Vec::new();
        for index in 0..15 {
            ids.push(
                store
                    .create_isolated_session(&profile(), parent, &spec, &format!("live-{index}"))
                    .await
                    .unwrap()
                    .sandbox
                    .id,
            );
        }
        assert_eq!(
            store
                .create_isolated_session(&profile(), parent, &spec, "after-release")
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        for id in ids {
            collect(&store, id).await;
        }
        for index in 15..64 {
            let key = if index == 15 {
                "after-release".to_string()
            } else {
                format!("history-{index}")
            };
            let child = store
                .create_isolated_session(&profile(), parent, &spec, &key)
                .await
                .unwrap();
            collect(&store, child.sandbox.id).await;
        }
        assert_eq!(
            store
                .sandbox_scope(parent)
                .await
                .unwrap()
                .allocated_to_children,
            limits(0, 0, 0)
        );
        assert_eq!(
            store
                .create_isolated_session(&profile(), parent, &spec, "too-many-history")
                .await
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            store
                .isolated_sessions(parent, None, 100)
                .await
                .unwrap()
                .items
                .len(),
            64
        );
    })
    .await;
}

#[tokio::test]
async fn schema_four_migration_and_reopen_preserve_prior_intent_and_request_keys() {
    use sqlx::{
        Connection,
        sqlite::{SqliteConnectOptions, SqliteConnection},
    };
    checked(|store, path| async move {
        let request = CreateSandbox::new("test", "fixture");
        let created = store
            .create_sandbox(&profile(), &request, "old-root")
            .await
            .unwrap();
        let id = created.sandbox.id;
        running(&store, id).await;
        let session = store
            .create_session(id, &SessionSpec::shell(), "old-session")
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
            .create_artifact(id, &CreateArtifact::new("old.bin"), "old-artifact")
            .await
            .unwrap();
        let context = store
            .create_code_context(id, &CodeContextSpec::default(), "old-context")
            .await
            .unwrap();
        store.dispatch_code_context(context.id).await.unwrap();
        store
            .close_code_context(context.id, "old-close")
            .await
            .unwrap();
        let installation = store.installation_id();
        store.close().await;
        let mut connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path))
                .await
                .unwrap();
        let result = sqlx::raw_sql(
            "DROP TABLE image_jobs;DROP TRIGGER credential_policy_fenced;DROP TRIGGER credential_controller_collecting;DROP TABLE credential_audit_deliveries;DROP TABLE credential_controller_history;DROP TABLE credential_epochs;DROP TABLE network_create_dispatches;DROP TABLE network_policy_applied_sources;DROP TABLE network_policy_changes;DROP TABLE network_policy_users;DROP TABLE network_policy_events;DROP TABLE network_policies;DROP TABLE network_controller_events;DROP TABLE network_controllers;DROP TABLE network_allocation_events;DROP TABLE network_allocations;DROP TABLE sandbox_scopes;UPDATE meta SET value='4' WHERE key='schema_version'",
        )
        .execute(&mut connection)
        .await;
        connection.close().await.unwrap();
        result.unwrap();
        let migrated = Store::open(&path).await.unwrap();
        let result = AssertUnwindSafe(async {
            assert_eq!(migrated.installation_id(), installation);
            assert_eq!(
                migrated
                    .create_sandbox(&profile(), &request, "old-root")
                    .await
                    .unwrap()
                    .sandbox
                    .id,
                id
            );
            let scope = migrated.sandbox_scope(id).await.unwrap();
            assert_eq!(scope.parent_id, None);
            assert_eq!(scope.root_id, id);
            assert_eq!(scope.depth, 0);
            assert_eq!(scope.envelope, request.resources);
            assert!(scope.child_budget.is_none() && scope.feature_limit.is_none());
            assert_eq!(
                migrated
                    .session_control(session.execution.id, 1)
                    .await
                    .unwrap()
                    .receipt
                    .state,
                SessionControlState::Pending
            );
            assert_eq!(
                migrated
                    .artifact_created(artifact.artifact.id)
                    .await
                    .unwrap()
                    .operation
                    .id,
                artifact.operation.id
            );
            let pending = migrated.code_context(context.id).await.unwrap();
            assert!(pending.dispatched);
            assert_eq!(
                pending.context.desired_state,
                CodeContextDesiredState::Closed
            );
        })
        .catch_unwind()
        .await;
        migrated.close().await;
        drop(migrated);
        result.unwrap();
        let reopened = Store::open(&path).await.unwrap();
        let result = reopened.sandbox_scope(id).await;
        reopened.close().await;
        drop(reopened);
        assert_eq!(result.unwrap().root_id, id);
    })
    .await;
}
