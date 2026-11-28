//! File-backed policy/version transactions. All runtime/controller receipts in
//! this file are synthetic and establish no actual lease or advertised profile.
use chrono::Utc;
use futures_util::FutureExt;
use goldenhoop_egress::{Allocation, EffectivePolicyReceipt, ProtectedBindingReceipt};
use goldenhoop_policy::{Packet, Transport};
use goldenhoop_protocol::*;
use goldenhoop_runtime::RuntimeHandle;
use goldenhoop_store::*;
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{future::Future, panic::AssertUnwindSafe, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
struct Fixture {
    path: PathBuf,
    pools: Arc<Mutex<Vec<Store>>>,
}
impl Fixture {
    async fn open(&self) -> Store {
        let store = Store::open(&self.path).await.unwrap();
        self.pools.lock().await.push(store.clone());
        store
    }
}
async fn checked<F, Fut>(test: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = ()>,
{
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture {
        path: dir.path().join("control.db"),
        pools: Default::default(),
    };
    let result = AssertUnwindSafe(test(fixture.clone())).catch_unwind().await;
    for store in fixture.pools.lock().await.drain(..) {
        store.close().await;
    }
    let root = dir.path().to_owned();
    dir.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
fn policy(destinations: &[&str]) -> NetworkPolicy {
    NetworkPolicy {
        default_action: NetworkAction::Deny,
        rules: destinations
            .iter()
            .map(|d| NetworkRule {
                destination: (*d).into(),
                ports: vec![443],
                action: NetworkAction::Allow,
            })
            .collect(),
    }
}
fn budget(nodes: u32) -> ResourceLimits {
    ResourceLimits {
        cpu_millis: 1000 * nodes,
        memory_bytes: 1024 * 1024 * 1024 * u64::from(nodes),
        pids: 256 * nodes,
    }
}
fn profile() -> RuntimeProfile {
    serde_json::from_value(serde_json::json!({"id":"policy-tree-test","placement":"local","isolation":"gvisor","availability":"available","capabilities":["commands","files","network_isolation","network_policy","isolated_sessions"],"max_resources":{"cpu_millis":16000,"memory_bytes":34359738368_u64,"pids":4096},"max_ttl_seconds":86400})).unwrap()
}
async fn setup(store: &Store) -> WorkerRegistration {
    let operator = NetworkOperatorPolicy {
        deny_always: vec![NetworkRule {
            destination: "127.0.0.0/8".into(),
            ports: vec![],
            action: NetworkAction::Deny,
        }],
        allow_always: vec![NetworkRule {
            destination: "93.184.216.36".into(),
            ports: vec![443],
            action: NetworkAction::Allow,
        }],
        tcp_cap: Some(vec![443]),
    };
    store.bind_network_operator(&operator).await.unwrap();
    let worker = WorkerRegistration {
        id: Uuid::new_v4(),
        endpoint: "http://127.0.0.1:1".into(),
        token: "synthetic-test".into(),
        heartbeat: Utc::now(),
        profiles: vec![profile()],
    };
    store.register_worker(&worker).await.unwrap();
    worker
}
async fn root(store: &Store, network: NetworkPolicy) -> Uuid {
    let mut request = CreateSandbox::new("policy-tree-test", "fixture");
    request.ttl_seconds = 600;
    request.network = network;
    request.child_budget = Some(budget(3));
    store
        .create_sandbox(&profile(), &request, &Uuid::new_v4().to_string())
        .await
        .unwrap()
        .sandbox
        .id
}
async fn child(store: &Store, parent: Uuid, network: NetworkPolicy) -> Uuid {
    store
        .create_isolated_session(
            &profile(),
            parent,
            &CreateIsolatedSession {
                network: Some(network),
                child_budget: Some(budget(2)),
                ..Default::default()
            },
            &Uuid::new_v4().to_string(),
        )
        .await
        .unwrap()
        .sandbox
        .id
}
async fn stage(store: &Store, id: Uuid, index: u32) -> NetworkPolicyControl {
    stage_with_source(store, id, index, true).await
}
async fn stage_with_source(
    store: &Store,
    id: Uuid,
    index: u32,
    public: bool,
) -> NetworkPolicyControl {
    let reserved = store.reserve_network(id, Uuid::new_v4()).await.unwrap();
    let network = store
        .begin_network_provisioning(id, reserved.generation, reserved.revision)
        .await
        .unwrap();
    let allocation = Allocation {
        installation_id: store.installation_id(),
        sandbox_id: id,
        generation: network.generation,
        bridge: network.bridge.clone(),
        ifindex: index,
    };
    let checkpoint:ProtectedBindingReceipt=serde_json::from_value(serde_json::json!({"allocation":allocation,"source":{"endpoint":{"port":format!("veth{}",index+1),"ifindex":index+1,"mac":"02:00:00:00:00:02","ipv4":"10.42.0.2","ipv6":"fd42::2"},"gateway_mac":"02:00:00:00:00:01","gateway4":"10.42.0.1","gateway6":"fd42::1"},"destinations":{"scope":{"host_addresses":["10.42.0.1","fd42::1"],"control_addresses":[],"private_exceptions":[]},"dns":[{"address":"10.42.0.1","port":40000},{"address":"fd42::1","port":40001}]},"revision":3,"expires_at":store.sandbox(id).await.unwrap().sandbox.expires_at,"observed_at":Utc::now()})).unwrap();
    let network_id = Uuid::new_v4().simple().to_string().repeat(2);
    store
        .bind_native_network(
            id,
            network.generation,
            network.token.unwrap(),
            NetworkNativeBinding {
                network_id: network_id.clone(),
                allocation: allocation.clone(),
            },
        )
        .await
        .unwrap();
    store
        .bind_network(
            id,
            network.generation,
            network.token.unwrap(),
            NetworkBinding {
                network_id,
                allocation,
                source: checkpoint.source.clone(),
                destinations: checkpoint.destinations.clone(),
            },
        )
        .await
        .unwrap();
    let mut sandbox = store.sandbox(id).await.unwrap();
    sandbox.sandbox.state = SandboxState::Starting;
    sandbox.handle = Some(RuntimeHandle {
        sandbox_id: id,
        profile: "policy-tree-test".into(),
        backend_ref: Uuid::new_v4().simple().to_string().repeat(2),
    });
    store.observe(sandbox).await.unwrap();
    if public {
        store
            .stage_public_network_policy(
                id,
                network.generation,
                checkpoint,
                "8.8.8.8:53".parse().unwrap(),
            )
            .await
            .unwrap()
    } else {
        store
            .stage_network_policy(
                id,
                network.generation,
                checkpoint,
                "8.8.8.8:53".parse().unwrap(),
                goldenhoop_egress::Config {
                    policies: vec![NetworkPolicy::default()],
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }
}
async fn claim(store: &Store, id: Uuid, worker: &WorkerRegistration) -> NetworkPolicyControl {
    let record = store.network_policy(id).await.unwrap();
    let controller = store
        .reserve_network_controller(
            id,
            record.allocation_generation,
            Uuid::new_v4(),
            &format!("sha256:{}", "c".repeat(64)),
        )
        .await
        .unwrap();
    let creating = store
        .begin_controller_create(id, controller.controller_generation, controller.revision)
        .await
        .unwrap();
    let physical = controller
        .controller_generation
        .simple()
        .to_string()
        .repeat(2);
    let created = store
        .record_controller_created(
            id,
            controller.controller_generation,
            creating.create_token.unwrap(),
            &physical,
        )
        .await
        .unwrap();
    let starting = store
        .begin_controller_start(id, controller.controller_generation, created.revision)
        .await
        .unwrap();
    store
        .record_controller_running(
            id,
            controller.controller_generation,
            starting.start_token.unwrap(),
            &physical,
        )
        .await
        .unwrap();
    store
        .claim_network_policy(
            id,
            record.revision,
            worker.id,
            controller.controller_generation,
        )
        .await
        .unwrap()
}
fn receipt(record: &NetworkPolicyControl) -> EffectivePolicyReceipt {
    let mut binding = record.checkpoint.clone();
    binding.revision = record.revision + 10;
    binding.observed_at = Utc::now();
    EffectivePolicyReceipt {
        binding,
        config_sha256: record.config_sha256.clone(),
        native_sha256: "e".repeat(64),
        lease_remaining_milliseconds: 8000,
    }
}
async fn ack(store: &Store, id: Uuid) -> NetworkPolicyControl {
    let record = store.network_policy(id).await.unwrap();
    let owner = record.owner.as_ref().unwrap();
    let applying = store
        .begin_network_policy_apply(id, record.revision, owner)
        .await
        .unwrap();
    store
        .confirm_network_policy(
            id,
            applying.revision,
            owner,
            applying.attempt.unwrap(),
            receipt(&applying),
        )
        .await
        .unwrap()
}
async fn running(store: &Store, id: Uuid) {
    let mut sandbox = store.sandbox(id).await.unwrap();
    sandbox.sandbox.state = SandboxState::Running;
    store.observe(sandbox).await.unwrap();
}
async fn ready_root(store: &Store, worker: &WorkerRegistration) -> Uuid {
    let id = root(store, policy(&["93.184.216.34"])).await;
    stage(store, id, 40).await;
    claim(store, id, worker).await;
    ack(store, id).await;
    running(store, id).await;
    id
}

#[tokio::test]
async fn creation_dispatches_refuse_replay_and_empty_absence_until_settlement_survives_reopen() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        setup(&store).await;
        let id = root(&store, NetworkPolicy::default()).await;
        let reserved = store.reserve_network(id, Uuid::new_v4()).await.unwrap();
        let network = store
            .begin_network_provisioning(id, reserved.generation, reserved.revision)
            .await
            .unwrap();
        assert!(
            store
                .begin_network_create(
                    id,
                    network.generation,
                    NetworkCreateKind::Workload,
                    &"a".repeat(64)
                )
                .await
                .is_err()
        );
        let bridge = store
            .begin_network_create(
                id,
                network.generation,
                NetworkCreateKind::Bridge,
                &"a".repeat(64),
            )
            .await
            .unwrap();
        assert!(bridge.settled_at.is_none());
        assert_eq!(
            store
                .require_network_creates_settled(id)
                .await
                .unwrap_err()
                .code,
            ErrorCode::BackendUnavailable
        );
        assert_eq!(
            store
                .begin_network_create(
                    id,
                    network.generation,
                    NetworkCreateKind::Bridge,
                    &"a".repeat(64)
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert!(
            store
                .settle_network_create(id, NetworkCreateKind::Workload, bridge.attempt, None)
                .await
                .is_err()
        );
        assert!(
            store
                .settle_network_create(id, NetworkCreateKind::Bridge, Uuid::new_v4(), None)
                .await
                .is_err()
        );
        let native = NetworkNativeBinding {
            network_id: "b".repeat(64),
            allocation: Allocation {
                installation_id: store.installation_id(),
                sandbox_id: id,
                generation: network.generation,
                bridge: network.bridge.clone(),
                ifindex: 92,
            },
        };
        store
            .bind_native_network(id, network.generation, network.token.unwrap(), native)
            .await
            .unwrap();
        let mut sandbox = store.sandbox(id).await.unwrap();
        sandbox.sandbox.state = SandboxState::Starting;
        store.observe(sandbox).await.unwrap();
        assert!(
            store
                .begin_network_create(
                    id,
                    network.generation,
                    NetworkCreateKind::Workload,
                    &"c".repeat(64)
                )
                .await
                .is_err()
        );
        store
            .settle_network_create(
                id,
                NetworkCreateKind::Bridge,
                bridge.attempt,
                Some(&"b".repeat(64)),
            )
            .await
            .unwrap();
        store.require_network_creates_settled(id).await.unwrap();
        let workload = store
            .begin_network_create(
                id,
                network.generation,
                NetworkCreateKind::Workload,
                &"c".repeat(64),
            )
            .await
            .unwrap();
        assert!(
            store
                .begin_network_create(
                    id,
                    network.generation,
                    NetworkCreateKind::Workload,
                    &"c".repeat(64)
                )
                .await
                .is_err()
        );
        store.close().await;
        let reopened = fixture.open().await;
        let restored = reopened
            .network_create_dispatch(id, NetworkCreateKind::Workload)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.attempt, workload.attempt);
        assert!(restored.settled_at.is_none() && restored.physical_id.is_none());
        reopened
            .set_desired(id, DesiredState::Terminated, "close-uncertain-create")
            .await
            .unwrap();
        let current = reopened.network_allocation(id).await.unwrap();
        let collecting = reopened
            .begin_network_collection(id, current.generation, current.revision)
            .await
            .unwrap();
        let absence = || NetworkAbsence {
            provisioning_settled: true,
            endpoints_absent: true,
            network_absent: true,
            bridge_absent: true,
            owned_tables_absent: true,
            observed_at: Utc::now(),
        };
        // Even every caller-supplied absence bit cannot settle a pending write.
        assert_eq!(
            reopened
                .confirm_network_absence(
                    id,
                    current.generation,
                    collecting.token.unwrap(),
                    absence()
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::BackendUnavailable
        );
        assert!(
            reopened
                .settle_network_create(
                    id,
                    NetworkCreateKind::Workload,
                    workload.attempt,
                    Some("container-name")
                )
                .await
                .is_err()
        );
        let settled = reopened
            .settle_network_create(
                id,
                NetworkCreateKind::Workload,
                workload.attempt,
                Some(&"d".repeat(64)),
            )
            .await
            .unwrap();
        let replay = reopened
            .settle_network_create(
                id,
                NetworkCreateKind::Workload,
                workload.attempt,
                Some(&"d".repeat(64)),
            )
            .await
            .unwrap();
        assert_eq!(settled.settled_at, replay.settled_at);
        assert!(
            reopened
                .settle_network_create(
                    id,
                    NetworkCreateKind::Workload,
                    workload.attempt,
                    Some(&"e".repeat(64))
                )
                .await
                .is_err()
        );
        reopened.require_network_creates_settled(id).await.unwrap();
        assert_eq!(
            reopened
                .confirm_network_absence(
                    id,
                    current.generation,
                    collecting.token.unwrap(),
                    absence()
                )
                .await
                .unwrap()
                .phase,
            NetworkPhase::Collected
        );
        assert!(
            reopened
                .begin_network_create(
                    id,
                    current.generation,
                    NetworkCreateKind::Workload,
                    &"c".repeat(64)
                )
                .await
                .is_err()
        );
    })
    .await;
}

#[tokio::test]
async fn schema_twelve_upgrade_preserves_public_intent_and_acknowledgement_bytes_without_inventing_dispatches()
 {
    checked(|fixture| async move {
        let store=fixture.open().await;
        let worker=setup(&store).await;
        let id=ready_root(&store,&worker).await;
        let changed=store.set_public_network_policy(id,&SetNetworkPolicy { expected_revision:0,policy:policy(&[]) },"before-v13").await.unwrap();
        ack(&store,id).await;
        assert_eq!(store.operation(changed.operation.id).await.unwrap().state,OperationState::Succeeded);
        store.close().await;
        let options=SqliteConnectOptions::new().filename(&fixture.path);
        let mut connection=SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::raw_sql("DROP TABLE snapshot_execution_candidates;DROP TABLE snapshots;DROP TABLE image_jobs;DROP TRIGGER credential_policy_fenced;DROP TRIGGER credential_controller_collecting;DROP TABLE credential_audit_deliveries;DROP TABLE credential_controller_history;DROP TABLE credential_epochs;DROP TABLE network_create_dispatches;UPDATE meta SET value='12' WHERE key='schema_version'").execute(&mut connection).await.unwrap();
        async fn snapshot(connection:&mut SqliteConnection)->Vec<String> {
            let mut values=Vec::new();
            for query in [
                "SELECT payload FROM sandboxes ORDER BY id",
                "SELECT payload FROM operations ORDER BY id",
                "SELECT payload FROM network_policies ORDER BY sandbox_id",
                "SELECT payload FROM network_policy_events ORDER BY sandbox_id,revision",
                "SELECT payload FROM network_policy_changes ORDER BY operation_id",
                "SELECT sandbox_id||'|'||revision||'|'||policy FROM network_policy_users ORDER BY sandbox_id",
                "SELECT sandbox_id||'|'||source_id||'|'||source_revision||'|'||source_sha256||'|'||control_revision FROM network_policy_applied_sources ORDER BY sandbox_id,source_id,source_revision",
                "SELECT payload FROM network_controllers ORDER BY controller_generation",
                "SELECT payload FROM network_controller_events ORDER BY controller_generation,revision",
            ] {
                values.extend(sqlx::query_scalar::<_,String>(query).fetch_all(&mut *connection).await.unwrap());
            }
            values
        }
        let before=snapshot(&mut connection).await;
        connection.close().await.unwrap();
        let upgraded=fixture.open().await;
        assert_eq!(upgraded.public_network_policy(id).await.unwrap().revision,1);
        for kind in [NetworkCreateKind::Bridge,NetworkCreateKind::Workload] {
            assert!(upgraded.network_create_dispatch(id,kind).await.unwrap().is_none());
        }
        let mut connection=SqliteConnection::connect_with(&options).await.unwrap();
        let version:String=sqlx::query_scalar("SELECT value FROM meta WHERE key='schema_version'").fetch_one(&mut connection).await.unwrap();
        assert_eq!(version,"20");
        assert_eq!(snapshot(&mut connection).await,before);
        connection.close().await.unwrap();
    }).await;
}

#[tokio::test]
async fn internal_profile_probe_marker_is_atomic_hidden_and_retained_for_recovery() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let public = root(&store, NetworkPolicy::default()).await;
        let mut request = CreateSandbox::new("policy-tree-test", "fixture");
        request.ttl_seconds = 600;
        request.child_budget = Some(budget(3));
        let probe = store
            .create_network_profile_probe(&profile(), &request, "private-probe")
            .await
            .unwrap();
        assert_eq!(
            store
                .create_network_profile_probe(&profile(), &request, "private-probe")
                .await
                .unwrap()
                .sandbox
                .id,
            probe.sandbox.id
        );
        assert_eq!(
            store.network_profile_probes().await.unwrap()[0].sandbox.id,
            probe.sandbox.id
        );
        assert_eq!(
            store
                .list_sandboxes(None, 100)
                .await
                .unwrap()
                .items
                .iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
            vec![public]
        );
        stage(&store, probe.sandbox.id, 88).await;
        claim(&store, probe.sandbox.id, &worker).await;
        ack(&store, probe.sandbox.id).await;
        running(&store, probe.sandbox.id).await;
        let child = child(&store, probe.sandbox.id, NetworkPolicy::default()).await;
        assert!(
            store
                .list_sandboxes(None, 100)
                .await
                .unwrap()
                .items
                .iter()
                .all(|s| s.id != child && s.id != probe.sandbox.id)
        );
        store
            .set_desired(
                probe.sandbox.id,
                DesiredState::Terminated,
                "probe-interrupted",
            )
            .await
            .unwrap();
        assert_eq!(
            store.operation(probe.operation.id).await.unwrap().state,
            OperationState::Pending
        );
        store.close().await;
        let reopened = fixture.open().await;
        let pending = reopened.network_profile_probes().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].sandbox.id, probe.sandbox.id);
        assert_eq!(pending[0].sandbox.desired_state, DesiredState::Terminated);
        assert_eq!(
            reopened.effective_desired(child).await.unwrap(),
            DesiredState::Terminated
        );
        // No runtime absence is inferred from this metadata-only recovery list.
        assert_ne!(pending[0].sandbox.cleanup, CleanupState::Complete);
    })
    .await;
}

#[tokio::test]
async fn private_probe_completion_requires_running_history_and_collected_normal_termination() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        setup(&store).await;
        let mut completed = Vec::new();
        // Synthetic state observations test only the durable operation contract.
        // They do not establish native application, absence or availability.
        for (key, ran, terminal) in [
            ("never-ran", false, SandboxState::Terminated),
            ("failed-after-running", true, SandboxState::Failed),
            ("normally-collected", true, SandboxState::Terminated),
        ] {
            let request = CreateSandbox::new("policy-tree-test", "fixture");
            let probe = store
                .create_network_profile_probe(&profile(), &request, key)
                .await
                .unwrap();
            let id = probe.sandbox.id;
            store
                .finish_operations(id, "network_profile_probe", OperationState::Running, None)
                .await
                .unwrap();
            assert!(
                store
                    .finish_operations(id, "network_profile_probe", OperationState::Succeeded, None)
                    .await
                    .is_err()
            );
            if ran {
                for state in [SandboxState::Starting, SandboxState::Running] {
                    let mut stored = store.sandbox(id).await.unwrap();
                    stored.sandbox.state = state;
                    store.observe(stored).await.unwrap();
                }
            }
            store
                .set_desired(id, DesiredState::Terminated, &format!("close-{key}"))
                .await
                .unwrap();
            let mut stored = store.sandbox(id).await.unwrap();
            stored.sandbox.state = SandboxState::Stopping;
            stored.sandbox.cleanup = CleanupState::Pending;
            store.observe(stored).await.unwrap();
            assert!(
                store
                    .finish_operations(id, "network_profile_probe", OperationState::Succeeded, None)
                    .await
                    .is_err()
            );
            let mut stored = store.sandbox(id).await.unwrap();
            stored.sandbox.state = terminal;
            stored.sandbox.cleanup = CleanupState::Complete;
            store.observe(stored).await.unwrap();
            assert_eq!(
                store.operation(probe.operation.id).await.unwrap().state,
                OperationState::Running
            );
            assert!(
                store
                    .finish_operations(id, "unrecognized_kind", OperationState::Succeeded, None)
                    .await
                    .is_err()
            );
            let result = store
                .finish_operations(id, "network_profile_probe", OperationState::Succeeded, None)
                .await;
            if ran && terminal == SandboxState::Terminated {
                result.unwrap();
                completed.push(probe.operation.id);
            } else {
                assert_eq!(result.unwrap_err().code, ErrorCode::InvalidState);
                store
                    .finish_operations(id, "network_profile_probe", OperationState::Failed, None)
                    .await
                    .unwrap();
            }
        }
        assert!(store.network_profile_probes().await.unwrap().is_empty());
        assert!(
            store
                .list_sandboxes(None, 100)
                .await
                .unwrap()
                .items
                .is_empty()
        );
        store.close().await;
        let reopened = fixture.open().await;
        for id in completed {
            let operation = reopened.operation(id).await.unwrap();
            assert_eq!(operation.state, OperationState::Succeeded);
            assert!(operation.finished_at.is_some());
        }
        assert!(reopened.network_profile_probes().await.unwrap().is_empty());
    })
    .await;
}

#[tokio::test]
async fn pause_resume_does_not_supersede_independent_pending_policy_intent() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let id = ready_root(&store, &worker).await;
        store
            .set_desired(id, DesiredState::Paused, "pause-intent")
            .await
            .unwrap();
        for state in [SandboxState::Pausing, SandboxState::Paused] {
            let mut stored = store.sandbox(id).await.unwrap();
            stored.sandbox.state = state;
            store.observe(stored).await.unwrap();
        }
        store
            .finish_operations(id, "pause", OperationState::Succeeded, None)
            .await
            .unwrap();
        let request = SetNetworkPolicy {
            expected_revision: 0,
            policy: policy(&[]),
        };
        let changed = store
            .set_public_network_policy(id, &request, "paused-policy")
            .await
            .unwrap();
        store.settle_network_policy_changes().await.unwrap();
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Pending
        );
        store
            .set_desired(id, DesiredState::Running, "resume-intent")
            .await
            .unwrap();
        let replay = store
            .set_public_network_policy(id, &request, "paused-policy")
            .await
            .unwrap();
        assert_eq!(replay.operation.id, changed.operation.id);
        assert_eq!(replay.operation.state, OperationState::Pending);
        store.settle_network_policy_changes().await.unwrap();
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Pending
        );
        // Synthetic acknowledgement only; the real supported-host test must
        // still establish the fresh physical epoch and worker-held lease.
        ack(&store, id).await;
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Succeeded
        );
    })
    .await;
}

#[tokio::test]
async fn schema_eleven_upgrade_preserves_private_history_without_promoting_it_to_public_intent() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let id = root(&store, NetworkPolicy::default()).await;
        stage_with_source(&store, id, 52, false).await;
        claim(&store, id, &worker).await;
        let active = ack(&store, id).await;
        assert!(active.public_inputs.is_none());
        running(&store, id).await;
        store.close().await;
        let options = SqliteConnectOptions::new().filename(&fixture.path);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::raw_sql("DROP TABLE snapshot_execution_candidates;DROP TABLE snapshots;DROP TABLE image_jobs;DROP TRIGGER credential_policy_fenced;DROP TRIGGER credential_controller_collecting;DROP TABLE credential_audit_deliveries;DROP TABLE credential_controller_history;DROP TABLE credential_epochs;DROP TABLE network_create_dispatches;DROP TABLE network_policy_applied_sources;DROP TABLE network_policy_changes;DROP TABLE network_policy_users;DELETE FROM meta WHERE key='network_operator_policy';UPDATE meta SET value='11' WHERE key='schema_version'")
            .execute(&mut connection).await.unwrap();
        async fn snapshot(connection: &mut SqliteConnection) -> Vec<String> {
            let mut values = Vec::new();
            for query in [
                "SELECT payload FROM sandboxes ORDER BY payload",
                "SELECT payload FROM operations ORDER BY payload",
                "SELECT payload FROM network_policies ORDER BY payload",
                "SELECT payload FROM network_policy_events ORDER BY payload",
                "SELECT payload FROM network_controllers ORDER BY payload",
                "SELECT payload FROM network_controller_events ORDER BY payload",
            ] {
                values.extend(sqlx::query_scalar::<_, String>(query).fetch_all(&mut *connection).await.unwrap());
            }
            values
        }
        let before = snapshot(&mut connection).await;
        let raw: String = sqlx::query_scalar("SELECT payload FROM network_policies WHERE sandbox_id=?")
            .bind(id.to_string()).fetch_one(&mut connection).await.unwrap();
        assert!(!raw.contains("public_inputs"));
        connection.close().await.unwrap();
        let reopened = fixture.open().await;
        let restored = reopened.network_policy(id).await.unwrap();
        assert_eq!(serde_json::to_string(&restored).unwrap(), raw);
        assert_eq!(restored.phase, NetworkPolicyPhase::Active);
        assert!(restored.public_inputs.is_none());
        assert_eq!(reopened.public_network_policy(id).await.unwrap().revision, 0);
        assert_eq!(reopened.set_public_network_policy(id, &SetNetworkPolicy {
            expected_revision: 0,
            policy: policy(&["93.184.216.34"]),
        }, "legacy-is-private").await.unwrap_err().code, ErrorCode::UnsupportedCapability);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        let version: String = sqlx::query_scalar("SELECT value FROM meta WHERE key='schema_version'")
            .fetch_one(&mut connection).await.unwrap();
        assert_eq!(version, "20");
        assert_eq!(snapshot(&mut connection).await, before);
        let overrides: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM network_policy_users")
            .fetch_one(&mut connection).await.unwrap();
        assert_eq!(overrides, 0);
        connection.close().await.unwrap();
    }).await;
}
fn action(config: &goldenhoop_egress::Config, address: &str, port: u16) -> NetworkAction {
    config
        .model()
        .unwrap()
        .address_candidate(
            &Packet::new(address.parse().unwrap(), Transport::Tcp, Some(port)).unwrap(),
        )
        .action
}
#[tokio::test]
async fn effective_layers_keep_parent_constraints_and_the_immutable_operator_floor() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let root = ready_root(&store, &worker).await;
        let child = child(
            &store,
            root,
            policy(&["93.184.216.34", "93.184.216.35", "127.0.0.1"]),
        )
        .await;
        let record = stage(&store, child, 60).await;
        let (config, sources) = store.resolved_network_policy(child).await.unwrap();
        assert_eq!(
            sources
                .lineage
                .iter()
                .map(|s| s.sandbox_id)
                .collect::<Vec<_>>(),
            vec![root, child]
        );
        assert_eq!(record.public_inputs.as_ref(), Some(&sources));
        assert_eq!(config.policies.len(), 2);
        assert_eq!(action(&config, "93.184.216.34", 443), NetworkAction::Allow);
        assert_eq!(action(&config, "93.184.216.35", 443), NetworkAction::Deny);
        assert_eq!(action(&config, "93.184.216.36", 443), NetworkAction::Allow);
        assert_eq!(action(&config, "93.184.216.36", 80), NetworkAction::Deny);
        assert_eq!(action(&config, "127.0.0.1", 443), NetworkAction::Deny);
        assert_eq!(
            store.public_network_policy(child).await.unwrap().revision,
            0
        );
        assert!(
            store
                .bind_network_operator(&NetworkOperatorPolicy::default())
                .await
                .is_err()
        );
        assert!(
            store
                .update_network_policy(
                    child,
                    record.allocation_generation,
                    record.desired_revision,
                    config
                )
                .await
                .is_err()
        );
    })
    .await;
}
#[tokio::test]
async fn ancestor_change_fences_every_target_and_old_inflight_ack_cannot_complete_it() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let root = ready_root(&store, &worker).await;
        let child = child(&store, root, policy(&["93.184.216.34"])).await;
        stage(&store, child, 60).await;
        claim(&store, child, &worker).await;
        ack(&store, child).await;
        running(&store, child).await;
        let old = store.network_policy(child).await.unwrap();
        let old_attempt = store
            .begin_network_policy_apply(child, old.revision, old.owner.as_ref().unwrap())
            .await
            .unwrap();
        let request = SetNetworkPolicy {
            expected_revision: 0,
            policy: policy(&[]),
        };
        let changed = store
            .set_public_network_policy(root, &request, "ancestor-deny")
            .await
            .unwrap();
        assert_eq!(changed.policy.revision, 1);
        assert_eq!(changed.operation.state, OperationState::Pending);
        for id in [root, child] {
            let c = store.network_policy(id).await.unwrap();
            assert_eq!(c.phase, NetworkPolicyPhase::Pending);
            assert!(c.observation.is_none());
            assert_eq!(c.public_inputs.as_ref().unwrap().lineage[0].revision, 1);
            assert_eq!(
                store.sandbox(id).await.unwrap().sandbox.state,
                SandboxState::Unknown
            );
        }
        assert!(
            store
                .confirm_network_policy(
                    child,
                    old_attempt.revision,
                    old_attempt.owner.as_ref().unwrap(),
                    old_attempt.attempt.unwrap(),
                    receipt(&old_attempt)
                )
                .await
                .is_err()
        );
        ack(&store, root).await;
        running(&store, root).await;
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Pending
        );
        ack(&store, child).await;
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Succeeded
        );
        let replay = store
            .set_public_network_policy(root, &request, "ancestor-deny")
            .await
            .unwrap();
        assert_eq!(replay.operation.id, changed.operation.id);
        assert_eq!(replay.policy.revision, 1);
        assert_eq!(replay.operation.state, OperationState::Succeeded);
        assert!(
            store
                .set_public_network_policy(root, &request, "different-key-stale-version")
                .await
                .is_err()
        );
        assert_eq!(
            store.public_network_policy(child).await.unwrap().revision,
            0
        );
    })
    .await;
}
#[tokio::test]
async fn child_update_can_confirm_the_parent_constraint_without_replaying_an_old_full_config() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let root = ready_root(&store, &worker).await;
        let child = child(&store, root, policy(&["93.184.216.34"])).await;
        stage(&store, child, 60).await;
        claim(&store, child, &worker).await;
        ack(&store, child).await;
        running(&store, child).await;
        let parent = store
            .set_public_network_policy(
                root,
                &SetNetworkPolicy {
                    expected_revision: 0,
                    policy: policy(&[]),
                },
                "parent",
            )
            .await
            .unwrap();
        ack(&store, root).await;
        running(&store, root).await;
        let own = store
            .set_public_network_policy(
                child,
                &SetNetworkPolicy {
                    expected_revision: 0,
                    policy: policy(&["93.184.216.35"]),
                },
                "child",
            )
            .await
            .unwrap();
        let effective = store.resolved_network_policy(child).await.unwrap().0;
        assert_eq!(
            action(&effective, "93.184.216.35", 443),
            NetworkAction::Deny
        );
        ack(&store, child).await;
        for op in [parent.operation.id, own.operation.id] {
            assert_eq!(
                store.operation(op).await.unwrap().state,
                OperationState::Succeeded
            );
        }
    })
    .await;
}
#[tokio::test]
async fn pending_child_stages_current_lineage_and_keeps_parent_change_pending_until_confirmed() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let root = ready_root(&store, &worker).await;
        let child = child(&store, root, policy(&["93.184.216.34"])).await;
        let old = store.resolved_network_policy(child).await.unwrap().1;
        assert_eq!(old.lineage[0].revision, 0);
        let changed = store
            .set_public_network_policy(
                root,
                &SetNetworkPolicy {
                    expected_revision: 0,
                    policy: policy(&[]),
                },
                "pending-child",
            )
            .await
            .unwrap();
        ack(&store, root).await;
        running(&store, root).await;
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Pending
        );
        let staged = stage(&store, child, 60).await;
        assert_eq!(staged.public_inputs.unwrap().lineage[0].revision, 1);
        claim(&store, child, &worker).await;
        ack(&store, child).await;
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Succeeded
        );
    })
    .await;
}

#[tokio::test]
async fn supersession_replay_and_reopen_keep_unconfirmed_changes_distinct_from_application() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let root = ready_root(&store, &worker).await;
        let first_request = SetNetworkPolicy {
            expected_revision: 0,
            policy: policy(&[]),
        };
        let first = store
            .set_public_network_policy(root, &first_request, "first")
            .await
            .unwrap();
        let second = store
            .set_public_network_policy(
                root,
                &SetNetworkPolicy {
                    expected_revision: 1,
                    policy: policy(&["93.184.216.34"]),
                },
                "second",
            )
            .await
            .unwrap();
        assert_eq!(
            store.operation(first.operation.id).await.unwrap().state,
            OperationState::Cancelled
        );
        assert_eq!(
            store.operation(second.operation.id).await.unwrap().state,
            OperationState::Pending
        );
        let replay = store
            .set_public_network_policy(root, &first_request, "first")
            .await
            .unwrap();
        assert_eq!(replay.policy.revision, 1);
        assert_eq!(replay.operation.id, first.operation.id);
        assert_eq!(replay.operation.state, OperationState::Cancelled);
        let before = store.resolved_network_policy(root).await.unwrap().1;
        store.close().await;
        let reopened = fixture.open().await;
        assert_eq!(
            reopened.public_network_policy(root).await.unwrap().revision,
            2
        );
        assert_eq!(
            reopened.resolved_network_policy(root).await.unwrap().1,
            before
        );
        // The same registered owner can still acknowledge the current pending
        // version in this metadata test; no actual native proof is claimed.
        ack(&reopened, root).await;
        assert_eq!(
            reopened.operation(second.operation.id).await.unwrap().state,
            OperationState::Succeeded
        );
        assert_eq!(
            reopened.operation(first.operation.id).await.unwrap().state,
            OperationState::Cancelled
        );
    })
    .await;
}

#[tokio::test]
async fn legacy_descendant_refusal_rolls_back_the_entire_intent_fence_and_idempotency_reservation()
{
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let root = ready_root(&store, &worker).await;
        let child = child(&store, root, policy(&["93.184.216.34"])).await;
        let mut legacy = store.sandbox(child).await.unwrap();
        legacy.sandbox.state = SandboxState::Starting;
        store.observe(legacy.clone()).await.unwrap();
        legacy.sandbox.state = SandboxState::Running;
        store.observe(legacy).await.unwrap();
        let before = store.network_policy(root).await.unwrap();
        let request = SetNetworkPolicy {
            expected_revision: 0,
            policy: policy(&[]),
        };
        assert_eq!(
            store
                .set_public_network_policy(root, &request, "rollback")
                .await
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedCapability
        );
        let after = store.network_policy(root).await.unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.phase, NetworkPolicyPhase::Active);
        assert_eq!(store.public_network_policy(root).await.unwrap().revision, 0);
        assert_eq!(
            store.sandbox(root).await.unwrap().sandbox.state,
            SandboxState::Running
        );
        store
            .set_desired(child, DesiredState::Terminated, "close-legacy")
            .await
            .unwrap();
        let mut closed = store.sandbox(child).await.unwrap();
        closed.sandbox.state = SandboxState::Stopping;
        store.observe(closed.clone()).await.unwrap();
        closed.sandbox.state = SandboxState::Terminated;
        closed.sandbox.cleanup = CleanupState::Complete;
        store.observe(closed).await.unwrap();
        let changed = store
            .set_public_network_policy(root, &request, "rollback")
            .await
            .unwrap();
        ack(&store, root).await;
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Succeeded
        );
    })
    .await;
}

#[tokio::test]
async fn malformed_policy_and_feature_ceiling_never_mutate_intent_or_confirm_a_closed_self() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let worker = setup(&store).await;
        let root = ready_root(&store, &worker).await;
        let before = store.network_policy(root).await.unwrap();
        let bad = NetworkPolicy {
            default_action: NetworkAction::Deny,
            rules: vec![NetworkRule {
                destination: "http://user:secret@example.test".into(),
                ports: vec![443],
                action: NetworkAction::Allow,
            }],
        };
        assert!(
            store
                .set_public_network_policy(
                    root,
                    &SetNetworkPolicy {
                        expected_revision: 0,
                        policy: bad
                    },
                    "bad"
                )
                .await
                .is_err()
        );
        assert_eq!(store.public_network_policy(root).await.unwrap().revision, 0);
        assert_eq!(
            store.network_policy(root).await.unwrap().revision,
            before.revision
        );
        let changed = store
            .set_public_network_policy(
                root,
                &SetNetworkPolicy {
                    expected_revision: 0,
                    policy: policy(&[]),
                },
                "close-self",
            )
            .await
            .unwrap();
        store
            .set_desired(root, DesiredState::Terminated, "terminate-before-apply")
            .await
            .unwrap();
        store.settle_network_policy_changes().await.unwrap();
        assert_eq!(
            store.operation(changed.operation.id).await.unwrap().state,
            OperationState::Cancelled
        );
        assert!(
            store
                .set_public_network_policy(
                    root,
                    &SetNetworkPolicy {
                        expected_revision: 1,
                        policy: policy(&[])
                    },
                    "closed"
                )
                .await
                .is_err()
        );
        let mut limited = CreateSandbox::new("policy-tree-test", "fixture");
        limited.ttl_seconds = 600;
        limited.feature_limit = Some(
            [Capability::Commands, Capability::NetworkIsolation]
                .into_iter()
                .collect(),
        );
        let limited = store
            .create_sandbox(&profile(), &limited, "limited")
            .await
            .unwrap()
            .sandbox
            .id;
        stage(&store, limited, 80).await;
        claim(&store, limited, &worker).await;
        ack(&store, limited).await;
        running(&store, limited).await;
        assert_eq!(
            store
                .set_public_network_policy(
                    limited,
                    &SetNetworkPolicy {
                        expected_revision: 0,
                        policy: policy(&[])
                    },
                    "ceiling"
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            store.public_network_policy(limited).await.unwrap().revision,
            0
        );
    })
    .await;
}
