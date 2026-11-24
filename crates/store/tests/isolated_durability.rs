use futures_util::FutureExt;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use std::{
    collections::BTreeSet, future::Future, panic::AssertUnwindSafe, path::PathBuf, time::Duration,
};
use uuid::Uuid;

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
            Capability::Pause,
            Capability::NetworkIsolation,
            Capability::IsolatedSessions,
        ]),
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
    checked(|store, _| async move {
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
        let expiring = root(&store, Some(limits(100, 64, 16)), 1).await;
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
        tokio::time::sleep(Duration::from_millis(1100)).await;
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
            "DROP TABLE sandbox_scopes;UPDATE meta SET value='4' WHERE key='schema_version'",
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
