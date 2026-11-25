//! Real file-backed transactions; provider/kernel observations here are synthetic.
use chrono::{Duration, Utc};
use futures_util::FutureExt;
use goldenhoop_egress::{
    Allocation, DestinationDefinition, DestinationScope, Endpoint, SourceScope,
};
use goldenhoop_protocol::*;
use goldenhoop_store::{
    NetworkAbsence, NetworkAllocation, NetworkBinding, NetworkNativeBinding, NetworkPhase, Store,
};
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{collections::BTreeSet, future::Future, panic::AssertUnwindSafe, path::PathBuf};
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
        id: "test-network".into(),
        placement: Placement::Local,
        isolation: Isolation::Gvisor,
        availability: Availability::Available,
        capabilities: BTreeSet::from([
            Capability::Commands,
            Capability::Files,
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
fn request() -> CreateSandbox {
    serde_json::from_value(serde_json::json!({"profile":"test-network","image":"controlled@sha256:fixture","ttl_seconds":600})).unwrap()
}
async fn create(store: &Store) -> Uuid {
    store
        .create_sandbox(&profile(), &request(), &Uuid::new_v4().to_string())
        .await
        .unwrap()
        .sandbox
        .id
}
fn binding(record: &NetworkAllocation, index: u32, idchar: char) -> NetworkBinding {
    let source = SourceScope {
        endpoint: Endpoint {
            port: format!("veth{index}"),
            ifindex: index + 1,
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ipv4: "10.42.0.2".parse().unwrap(),
            ipv6: Some("fd42::2".parse().unwrap()),
        },
        gateway_mac: "02:00:00:00:00:01".parse().unwrap(),
        gateway4: "10.42.0.1".parse().unwrap(),
        gateway6: Some("fd42::1".parse().unwrap()),
    };
    NetworkBinding {
        network_id: idchar.to_string().repeat(64),
        allocation: Allocation {
            installation_id: record.installation_id,
            sandbox_id: record.sandbox_id,
            generation: record.generation,
            bridge: record.bridge.clone(),
            ifindex: index,
        },
        source,
        destinations: DestinationDefinition {
            scope: DestinationScope {
                host_addresses: vec!["10.42.0.1".parse().unwrap(), "fd42::1".parse().unwrap()],
                control_addresses: vec!["203.0.113.8".parse().unwrap()],
                private_exceptions: vec!["10.99.0.0/16".into()],
            },
            dns: vec![],
        }
        .canonical()
        .unwrap(),
    }
}
fn absence() -> NetworkAbsence {
    NetworkAbsence {
        provisioning_settled: true,
        endpoints_absent: true,
        network_absent: true,
        bridge_absent: true,
        owned_tables_absent: true,
        observed_at: Utc::now(),
    }
}
fn code<T: std::fmt::Debug>(result: Result<T, ApiError>, expected: ErrorCode) {
    assert_eq!(result.unwrap_err().code, expected);
}
async fn provision(store: &Store, id: Uuid) -> NetworkAllocation {
    let reserved = store.reserve_network(id, Uuid::new_v4()).await.unwrap();
    store
        .begin_network_provisioning(id, reserved.generation, reserved.revision)
        .await
        .unwrap()
}

/// Stage only the fixture clock after provisioning, rather than racing a
/// one-second real setup deadline. Actual expiry has a separate backend gate.
async fn expire_fixture_sandboxes(store: &Store, path: &std::path::Path, ids: &[Uuid]) {
    let mut snapshots = Vec::new();
    for id in ids {
        let mut sandbox = store.sandbox(*id).await.unwrap().sandbox;
        sandbox.created_at -= Duration::seconds(601);
        sandbox.expires_at -= Duration::seconds(601);
        snapshots.push((id.to_string(), serde_json::to_string(&sandbox).unwrap()));
    }
    let options = SqliteConnectOptions::new().filename(path);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    let result = async {
        for (id, payload) in snapshots {
            let changed = sqlx::query("UPDATE sandboxes SET payload=? WHERE id=?")
                .bind(payload)
                .bind(id)
                .execute(&mut connection)
                .await?;
            if changed.rows_affected() != 1 {
                return Err(sqlx::Error::RowNotFound);
            }
        }
        Ok::<_, sqlx::Error>(())
    }
    .await;
    connection.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn reservation_and_dispatch_survive_real_close_without_replaying_creation() {
    checked(|store, path| async move {
        let id = create(&store).await;
        let generation = Uuid::new_v4();
        let (left, right) = tokio::join!(
            store.reserve_network(id, generation),
            store.reserve_network(id, generation)
        );
        let reserved = left.unwrap();
        assert_eq!(reserved.network_name, right.unwrap().network_name);
        assert_eq!(reserved.revision, 0);
        code(
            store.reserve_network(id, Uuid::new_v4()).await,
            ErrorCode::Conflict,
        );
        let dispatched = store
            .begin_network_provisioning(id, generation, 0)
            .await
            .unwrap();
        let token = dispatched.token.unwrap();
        store.close().await;
        let reopened = Store::open(&path).await.unwrap();
        let work = AssertUnwindSafe(async {
            let recovered = reopened.network_allocation(id).await.unwrap();
            assert_eq!(recovered.phase, NetworkPhase::Provisioning);
            assert_eq!(recovered.token, Some(token));
            assert!(recovered.binding.is_none());
            code(
                reopened
                    .begin_network_provisioning(id, generation, recovered.revision)
                    .await,
                ErrorCode::Conflict,
            );
            let complete = binding(&recovered, 100, 'a');
            reopened
                .bind_native_network(id, generation, token, NetworkNativeBinding::from(&complete))
                .await
                .unwrap();
            let bound = reopened
                .bind_network(id, generation, token, complete)
                .await
                .unwrap();
            assert_eq!(bound.phase, NetworkPhase::Bound);
            assert!(bound.binding_fingerprint().unwrap().is_some());
            let history = reopened
                .network_allocation_history(id, None, 128)
                .await
                .unwrap();
            assert_eq!(
                history.iter().map(|r| r.phase).collect::<Vec<_>>(),
                vec![
                    NetworkPhase::Reserved,
                    NetworkPhase::Provisioning,
                    NetworkPhase::Provisioning,
                    NetworkPhase::Bound
                ]
            );
        })
        .catch_unwind()
        .await;
        reopened.close().await;
        if let Err(e) = work {
            std::panic::resume_unwind(e);
        }
    })
    .await;
}

#[tokio::test]
async fn immutable_binding_rejects_foreign_identity_scope_and_live_resource_collisions() {
    checked(|store, _| async move {
        let id = create(&store).await;
        let intent = provision(&store, id).await;
        let token = intent.token.unwrap();
        let good = binding(&intent, 100, 'a');
        store
            .bind_native_network(
                id,
                intent.generation,
                token,
                NetworkNativeBinding::from(&good),
            )
            .await
            .unwrap();
        for field in 0..5 {
            let mut bad = good.clone();
            match field {
                0 => bad.allocation.installation_id = Uuid::new_v4(),
                1 => bad.allocation.sandbox_id = Uuid::new_v4(),
                2 => bad.allocation.generation = Uuid::new_v4(),
                3 => bad.allocation.bridge = "ghforeign".into(),
                _ => bad.destinations.scope.host_addresses.clear(),
            };
            assert!(
                store
                    .bind_network(id, intent.generation, token, bad)
                    .await
                    .is_err()
            );
        }
        code(
            store
                .bind_network(id, intent.generation, Uuid::new_v4(), good.clone())
                .await,
            ErrorCode::Conflict,
        );
        let bound = store
            .bind_network(id, intent.generation, token, good.clone())
            .await
            .unwrap();
        let same = store
            .bind_network(id, intent.generation, token, good.clone())
            .await
            .unwrap();
        assert_eq!(bound.revision, same.revision);
        let mut changed = good.clone();
        changed.source.endpoint.mac = "02:00:00:00:00:04".parse().unwrap();
        code(
            store
                .bind_network(id, intent.generation, token, changed)
                .await,
            ErrorCode::Conflict,
        );
        let other = create(&store).await;
        let foreign = provision(&store, other).await;
        code(
            store
                .bind_native_network(
                    other,
                    foreign.generation,
                    foreign.token.unwrap(),
                    NetworkNativeBinding::from(&binding(&foreign, 200, 'a')),
                )
                .await,
            ErrorCode::Conflict,
        );
        code(
            store
                .bind_native_network(
                    other,
                    foreign.generation,
                    foreign.token.unwrap(),
                    NetworkNativeBinding::from(&binding(&foreign, 100, 'b')),
                )
                .await,
            ErrorCode::Conflict,
        );
        assert_eq!(
            store.network_allocation(other).await.unwrap().phase,
            NetworkPhase::Provisioning
        );
        assert_eq!(
            store
                .network_allocation_history(other, None, 128)
                .await
                .unwrap()
                .len(),
            2
        );
    })
    .await;
}

#[tokio::test]
async fn collection_requires_all_fresh_observations_and_gates_sandbox_cleanup() {
    checked(|store, _| async move {
        let id = create(&store).await;
        let intent = provision(&store, id).await;
        let mut terminal = store.sandbox(id).await.unwrap();
        terminal.sandbox.state = SandboxState::Failed;
        terminal.sandbox.cleanup = CleanupState::Complete;
        code(
            store.observe(terminal.clone()).await,
            ErrorCode::InvalidState,
        );
        let collecting = store
            .begin_network_collection(id, intent.generation, intent.revision)
            .await
            .unwrap();
        let token = collecting.token.unwrap();
        for field in 0..7 {
            let mut bad = absence();
            match field {
                0 => bad.endpoints_absent = false,
                1 => bad.network_absent = false,
                2 => bad.bridge_absent = false,
                3 => bad.owned_tables_absent = false,
                4 => bad.provisioning_settled = false,
                5 => bad.observed_at -= Duration::seconds(6),
                _ => bad.observed_at += Duration::seconds(6),
            };
            code(
                store
                    .confirm_network_absence(id, intent.generation, token, bad)
                    .await,
                ErrorCode::Conflict,
            );
        }
        code(
            store
                .confirm_network_absence(id, intent.generation, Uuid::new_v4(), absence())
                .await,
            ErrorCode::Conflict,
        );
        let observed = absence();
        let done = store
            .confirm_network_absence(id, intent.generation, token, observed.clone())
            .await
            .unwrap();
        let repeated = store
            .confirm_network_absence(id, intent.generation, token, observed)
            .await
            .unwrap();
        assert_eq!(done.revision, repeated.revision);
        store.observe(terminal).await.unwrap();
        assert_eq!(
            store.sandbox(id).await.unwrap().sandbox.cleanup,
            CleanupState::Complete
        );
        code(
            store
                .begin_network_provisioning(id, intent.generation, done.revision)
                .await,
            ErrorCode::Conflict,
        );
    })
    .await;
}

#[tokio::test]
async fn cancellation_wins_late_binding_and_residue_reopens_quota_without_rewriting_completion() {
    checked(|store, _| async move {
        let mut request = request();
        request.resources.cpu_millis = 16000;
        let created = store
            .create_sandbox(&profile(), &request, "full-root")
            .await
            .unwrap();
        let id = created.sandbox.id;
        let intent = provision(&store, id).await;
        let collecting = store
            .begin_network_collection(id, intent.generation, intent.revision)
            .await
            .unwrap();
        code(
            store
                .bind_network(
                    id,
                    intent.generation,
                    intent.token.unwrap(),
                    binding(&intent, 100, 'a'),
                )
                .await,
            ErrorCode::Conflict,
        );
        let done = store
            .confirm_network_absence(id, intent.generation, collecting.token.unwrap(), absence())
            .await
            .unwrap();
        let mut terminal = store.sandbox(id).await.unwrap();
        terminal.sandbox.state = SandboxState::Failed;
        terminal.sandbox.cleanup = CleanupState::Complete;
        store.observe(terminal).await.unwrap();
        store
            .finish_operations(
                id,
                "create",
                OperationState::Failed,
                Some(ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "controlled provisioning failure",
                )),
            )
            .await
            .unwrap();
        let completed = store.operation(created.operation.id).await.unwrap();
        let uncertain = store
            .reopen_network_collection(id, intent.generation, &"a".repeat(64))
            .await
            .unwrap();
        assert_eq!(uncertain.phase, NetworkPhase::Unknown);
        assert_eq!(uncertain.network_id, Some("a".repeat(64)));
        assert_eq!(
            store.sandbox(id).await.unwrap().sandbox.cleanup,
            CleanupState::Unknown
        );
        assert!(
            store
                .work()
                .await
                .unwrap()
                .iter()
                .any(|b| b.sandbox.id == id)
        );
        code(
            store
                .create_sandbox(&profile(), &self::request(), "over-quota")
                .await,
            ErrorCode::QuotaExceeded,
        );
        assert_eq!(
            serde_json::to_value(store.operation(created.operation.id).await.unwrap()).unwrap(),
            serde_json::to_value(completed).unwrap()
        );
        let history = store
            .network_allocation_history(id, Some(done.revision - 1), 128)
            .await
            .unwrap();
        assert_eq!(history[0].phase, NetworkPhase::Collected);
        assert!(history[0].absence.is_some());
        assert_eq!(history[1].phase, NetworkPhase::Unknown);
        code(
            store
                .confirm_network_absence(
                    id,
                    intent.generation,
                    collecting.token.unwrap(),
                    absence(),
                )
                .await,
            ErrorCode::Conflict,
        );
        code(
            store
                .reopen_network_collection(id, intent.generation, &"b".repeat(64))
                .await,
            ErrorCode::Conflict,
        );
        let fresh = store
            .begin_network_collection(id, intent.generation, uncertain.revision)
            .await
            .unwrap();
        store
            .confirm_network_absence(id, intent.generation, fresh.token.unwrap(), absence())
            .await
            .unwrap();
    })
    .await;
}

#[tokio::test]
async fn schema_five_upgrade_preserves_existing_identity_and_transactions() {
    checked(|store,path|async move{
    let id=create(&store).await;let installation=store.installation_id();let before=store.sandbox(id).await.unwrap().create_operation;store.close().await;
    let mut connection=SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path)).await.unwrap();
    let migration=sqlx::raw_sql("DROP TABLE network_policy_events;DROP TABLE network_policies;DROP TABLE network_controller_events;DROP TABLE network_controllers;DROP TABLE network_allocation_events;DROP TABLE network_allocations;UPDATE meta SET value='5' WHERE key='schema_version'").execute(&mut connection).await;connection.close().await.unwrap();migration.unwrap();
    let reopened=Store::open(&path).await.unwrap();let result=AssertUnwindSafe(async{
        assert_eq!(reopened.installation_id(),installation);assert_eq!(reopened.sandbox(id).await.unwrap().create_operation,before);assert_eq!(reopened.network_allocation_history(id,None,128).await.unwrap().len(),0);
        let reserved=reopened.reserve_network(id,Uuid::new_v4()).await.unwrap();assert_eq!(reserved.phase,NetworkPhase::Reserved);
        assert!(!profile().capabilities.contains(&Capability::NetworkPolicy));
    }).catch_unwind().await;reopened.close().await;if let Err(e)=result{std::panic::resume_unwind(e);}
}).await;
}

#[tokio::test]
async fn live_runtime_and_isolated_children_cannot_silently_acquire_the_initial_allocator() {
    checked(|store, _| async move {
        let mut spec = request();
        spec.child_budget = Some(ResourceLimits {
            cpu_millis: 1000,
            memory_bytes: 512 * 1024 * 1024,
            pids: 256,
        });
        let id = store
            .create_sandbox(&profile(), &spec, "root")
            .await
            .unwrap()
            .sandbox
            .id;
        let mut running = store.sandbox(id).await.unwrap();
        running.sandbox.state = SandboxState::Starting;
        store.observe(running.clone()).await.unwrap();
        running.sandbox.state = SandboxState::Running;
        store.observe(running).await.unwrap();
        code(
            store.reserve_network(id, Uuid::new_v4()).await,
            ErrorCode::InvalidState,
        );
        let child = store
            .create_isolated_session(
                &profile(),
                id,
                &CreateIsolatedSession {
                    resources: ResourceLimits {
                        cpu_millis: 100,
                        memory_bytes: 64 * 1024 * 1024,
                        pids: 16,
                    },
                    ttl_seconds: Some(120),
                    ..Default::default()
                },
                "child",
            )
            .await
            .unwrap()
            .sandbox
            .id;
        code(
            store.reserve_network(child, Uuid::new_v4()).await,
            ErrorCode::UnsupportedCapability,
        );
        code(store.network_allocation(child).await, ErrorCode::NotFound);
    })
    .await;
}

#[tokio::test]
async fn native_checkpoint_survives_close_without_fabricating_source_or_packet_confirmation() {
    checked(|store, path| async move {
        let id = create(&store).await;
        let dispatch = provision(&store, id).await;
        let token = dispatch.token.unwrap();
        let complete = binding(&dispatch, 100, 'a');
        code(
            store
                .bind_network(id, dispatch.generation, token, complete.clone())
                .await,
            ErrorCode::InvalidState,
        );
        let native = NetworkNativeBinding::from(&complete);
        let recorded = store
            .bind_native_network(id, dispatch.generation, token, native.clone())
            .await
            .unwrap();
        assert_eq!(recorded.phase, NetworkPhase::Provisioning);
        assert_eq!(recorded.revision, 2);
        assert!(recorded.binding.is_none() && recorded.binding_fingerprint().unwrap().is_none());
        store.close().await;
        let reopened = Store::open(&path).await.unwrap();
        let result = AssertUnwindSafe(async {
            let restored = reopened.network_allocation(id).await.unwrap();
            assert_eq!(restored.native_binding().unwrap().allocation.ifindex, 100);
            assert_eq!(
                restored.network_id.as_deref(),
                Some(complete.network_id.as_str())
            );
            let same = reopened
                .bind_native_network(id, dispatch.generation, token, native.clone())
                .await
                .unwrap();
            assert_eq!(same.revision, restored.revision);
            let mut wrong = native.clone();
            wrong.allocation.ifindex = 200;
            code(
                reopened
                    .bind_native_network(id, dispatch.generation, token, wrong)
                    .await,
                ErrorCode::Conflict,
            );
            let mut wrong = complete.clone();
            wrong.allocation.ifindex = 200;
            code(
                reopened
                    .bind_network(id, dispatch.generation, token, wrong)
                    .await,
                ErrorCode::Conflict,
            );
            let bound = reopened
                .bind_network(id, dispatch.generation, token, complete)
                .await
                .unwrap();
            assert_eq!(bound.revision, 3);
            assert_eq!(bound.native_binding().unwrap().allocation.ifindex, 100);
            assert_eq!(
                reopened
                    .network_allocation_history(id, None, 128)
                    .await
                    .unwrap()
                    .len(),
                4
            );
        })
        .catch_unwind()
        .await;
        reopened.close().await;
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    })
    .await;
}

#[tokio::test]
async fn native_checkpoint_refuses_foreign_scope_and_live_collisions_before_full_binding() {
    checked(|store, _| async move {
        let id = create(&store).await;
        let dispatch = provision(&store, id).await;
        let native = NetworkNativeBinding::from(&binding(&dispatch, 100, 'a'));
        for field in 0..7 {
            let mut wrong = native.clone();
            match field {
                0 => wrong.allocation.installation_id = Uuid::new_v4(),
                1 => wrong.allocation.sandbox_id = Uuid::new_v4(),
                2 => wrong.allocation.generation = Uuid::new_v4(),
                3 => wrong.allocation.bridge = "ghforeign".into(),
                4 => wrong.allocation.ifindex = 0,
                5 => wrong.network_id = "A".repeat(64),
                _ => wrong.network_id = "a".repeat(63),
            }
            assert!(
                store
                    .bind_native_network(id, dispatch.generation, dispatch.token.unwrap(), wrong)
                    .await
                    .is_err()
            );
        }
        code(
            store
                .bind_native_network(id, dispatch.generation, Uuid::new_v4(), native.clone())
                .await,
            ErrorCode::Conflict,
        );
        store
            .bind_native_network(id, dispatch.generation, dispatch.token.unwrap(), native)
            .await
            .unwrap();
        let other = create(&store).await;
        let other = provision(&store, other).await;
        for native in [
            NetworkNativeBinding::from(&binding(&other, 200, 'a')),
            NetworkNativeBinding::from(&binding(&other, 100, 'b')),
        ] {
            code(
                store
                    .bind_native_network(
                        other.sandbox_id,
                        other.generation,
                        other.token.unwrap(),
                        native,
                    )
                    .await,
                ErrorCode::Conflict,
            );
        }
        assert_eq!(
            store
                .network_allocation_history(other.sandbox_id, None, 128)
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(
            store
                .network_allocation(other.sandbox_id)
                .await
                .unwrap()
                .native
                .is_none()
        );
    })
    .await;
}

#[tokio::test]
async fn cancellation_expiry_and_collection_fence_new_native_and_complete_bindings() {
    checked(|store, path| async move {
        let id = create(&store).await;
        let dispatch = provision(&store, id).await;
        let complete = binding(&dispatch, 100, 'a');
        store
            .set_desired(id, DesiredState::Terminated, "cancel-before-native")
            .await
            .unwrap();
        code(
            store
                .bind_native_network(
                    id,
                    dispatch.generation,
                    dispatch.token.unwrap(),
                    NetworkNativeBinding::from(&complete),
                )
                .await,
            ErrorCode::Conflict,
        );
        let id = create(&store).await;
        let dispatch = provision(&store, id).await;
        let complete = binding(&dispatch, 200, 'b');
        let recorded = store
            .bind_native_network(
                id,
                dispatch.generation,
                dispatch.token.unwrap(),
                NetworkNativeBinding::from(&complete),
            )
            .await
            .unwrap();
        store
            .set_desired(id, DesiredState::Terminated, "cancel-after-native")
            .await
            .unwrap();
        code(
            store
                .bind_network(
                    id,
                    dispatch.generation,
                    dispatch.token.unwrap(),
                    complete.clone(),
                )
                .await,
            ErrorCode::Conflict,
        );
        let collecting = store
            .begin_network_collection(id, dispatch.generation, recorded.revision)
            .await
            .unwrap();
        code(
            store
                .bind_native_network(
                    id,
                    dispatch.generation,
                    dispatch.token.unwrap(),
                    NetworkNativeBinding::from(&complete),
                )
                .await,
            ErrorCode::Conflict,
        );
        assert_eq!(collecting.native_binding().unwrap().allocation.ifindex, 200);
        let done = store
            .confirm_network_absence(
                id,
                dispatch.generation,
                collecting.token.unwrap(),
                absence(),
            )
            .await
            .unwrap();
        assert_eq!(done.native_binding().unwrap().allocation.ifindex, 200);
        let spec = request();
        let created = store
            .create_sandbox(&profile(), &spec, "expiry-before-native")
            .await
            .unwrap();
        let dispatch = provision(&store, created.sandbox.id).await;
        let created = store
            .create_sandbox(&profile(), &spec, "expiry-before-complete")
            .await
            .unwrap();
        let later = provision(&store, created.sandbox.id).await;
        let complete = binding(&later, 400, 'd');
        store
            .bind_native_network(
                later.sandbox_id,
                later.generation,
                later.token.unwrap(),
                NetworkNativeBinding::from(&complete),
            )
            .await
            .unwrap();
        expire_fixture_sandboxes(&store, &path, &[dispatch.sandbox_id, later.sandbox_id]).await;
        code(
            store
                .bind_native_network(
                    dispatch.sandbox_id,
                    dispatch.generation,
                    dispatch.token.unwrap(),
                    NetworkNativeBinding::from(&binding(&dispatch, 300, 'c')),
                )
                .await,
            ErrorCode::Conflict,
        );
        assert_eq!(
            store
                .network_allocation_history(dispatch.sandbox_id, None, 128)
                .await
                .unwrap()
                .len(),
            2
        );
        code(
            store
                .bind_network(
                    later.sandbox_id,
                    later.generation,
                    later.token.unwrap(),
                    complete,
                )
                .await,
            ErrorCode::Conflict,
        );
        assert!(
            store
                .network_allocation(later.sandbox_id)
                .await
                .unwrap()
                .binding
                .is_none()
        );
    })
    .await;
}

#[tokio::test]
async fn schema_six_complete_binding_keeps_original_payload_and_history_bytes() {
    checked(|store, path| async move {
        let id = create(&store).await;
        let dispatch = provision(&store, id).await;
        let complete = binding(&dispatch, 100, 'a');
        let legacy = NetworkAllocation {
            phase: NetworkPhase::Bound,
            revision: 2,
            network_id: Some(complete.network_id.clone()),
            binding: Some(complete.clone()),
            ..dispatch.clone()
        };
        let payload = serde_json::to_string(&legacy).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&payload).unwrap().get("native").is_none());
        store.close().await;
        let options = SqliteConnectOptions::new().filename(&path);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        // Build the complete-binding row that the actual v6 writer emitted.
        // These kernel/provider identities are deliberately synthetic.
        sqlx::query("UPDATE network_allocations SET phase='bound',revision=2,network_id=?,ifindex=100,payload=? WHERE sandbox_id=?")
            .bind(&complete.network_id).bind(&payload).bind(id.to_string()).execute(&mut connection).await.unwrap();
        sqlx::query("INSERT INTO network_allocation_events(sandbox_id,revision,payload) VALUES(?,2,?)")
            .bind(id.to_string()).bind(&payload).execute(&mut connection).await.unwrap();
        sqlx::raw_sql("DROP TABLE network_policy_events;DROP TABLE network_policies;DROP TABLE network_controller_events;DROP TABLE network_controllers;UPDATE meta SET value='6' WHERE key='schema_version'").execute(&mut connection).await.unwrap();
        let before: Vec<String> = sqlx::query_scalar("SELECT payload FROM network_allocation_events ORDER BY revision").fetch_all(&mut connection).await.unwrap();
        connection.close().await.unwrap();
        let reopened = Store::open(&path).await.unwrap();
        let result = AssertUnwindSafe(async {
            let actual = reopened.network_allocation(id).await.unwrap();
            assert!(actual.native.is_none());
            assert_eq!(actual.native_binding().unwrap().allocation.ifindex, 100);
            assert_eq!(actual.revision, 2);
            let same = reopened.bind_native_network(id, dispatch.generation, dispatch.token.unwrap(), NetworkNativeBinding::from(&complete)).await.unwrap();
            assert_eq!(same.revision, 2);
            let same = reopened.bind_network(id, dispatch.generation, dispatch.token.unwrap(), complete).await.unwrap();
            assert_eq!(same.revision, 2);
            let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
            let version: String = sqlx::query_scalar("SELECT value FROM meta WHERE key='schema_version'").fetch_one(&mut connection).await.unwrap();
            let after: Vec<String> = sqlx::query_scalar("SELECT payload FROM network_allocation_events ORDER BY revision").fetch_all(&mut connection).await.unwrap();
            let current: String = sqlx::query_scalar("SELECT payload FROM network_allocations WHERE sandbox_id=?").bind(id.to_string()).fetch_one(&mut connection).await.unwrap();
            connection.close().await.unwrap();
            assert_eq!(version, "11");
            assert_eq!(before, after);
            assert_eq!(current, payload);
        }).catch_unwind().await;
        reopened.close().await;
        if let Err(error) = result { std::panic::resume_unwind(error); }
    }).await;
}
