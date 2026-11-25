//! Actual file-backed transactions; provider/kernel observations are synthetic.
use chrono::{Duration, Utc};
use futures_util::FutureExt;
use goldenhoop_egress::Allocation;
use goldenhoop_protocol::*;
use goldenhoop_store::*;
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{
    collections::BTreeSet, future::Future, panic::AssertUnwindSafe, path::PathBuf, sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
struct Fixture {
    path: PathBuf,
    stores: Arc<Mutex<Vec<Store>>>,
}
impl Fixture {
    async fn open(&self) -> Store {
        let store = Store::open(&self.path).await.unwrap();
        self.stores.lock().await.push(store.clone());
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
        stores: Arc::new(Mutex::new(Vec::new())),
    };
    let result = AssertUnwindSafe(test(fixture.clone())).catch_unwind().await;
    for store in fixture.stores.lock().await.drain(..) {
        store.close().await;
    }
    let root = dir.path().to_owned();
    dir.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
fn profile() -> RuntimeProfile {
    RuntimeProfile {
        id: "controller-test".into(),
        placement: Placement::Local,
        isolation: Isolation::Gvisor,
        availability: Availability::Available,
        capabilities: BTreeSet::from([
            Capability::Commands,
            Capability::Files,
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
async fn allocation(store: &Store, index: u32) -> NetworkAllocation {
    let request: CreateSandbox = serde_json::from_value(
        serde_json::json!({"profile":"controller-test","image":"fixture","ttl_seconds":600}),
    )
    .unwrap();
    let id = store
        .create_sandbox(&profile(), &request, &Uuid::new_v4().to_string())
        .await
        .unwrap()
        .sandbox
        .id;
    let reserved = store.reserve_network(id, Uuid::new_v4()).await.unwrap();
    let active = store
        .begin_network_provisioning(id, reserved.generation, reserved.revision)
        .await
        .unwrap();
    store
        .bind_native_network(
            id,
            active.generation,
            active.token.unwrap(),
            NetworkNativeBinding {
                network_id: format!("{index:064x}"),
                allocation: Allocation {
                    installation_id: store.installation_id(),
                    sandbox_id: id,
                    generation: active.generation,
                    bridge: active.bridge,
                    ifindex: index,
                },
            },
        )
        .await
        .unwrap()
}
fn image() -> String {
    format!("sha256:{}", "a".repeat(64))
}
async fn reserve(store: &Store, network: &NetworkAllocation) -> NetworkController {
    store
        .reserve_network_controller(
            network.sandbox_id,
            network.generation,
            Uuid::new_v4(),
            &image(),
        )
        .await
        .unwrap()
}

async fn pre_native(store: &Store, provision: bool) -> NetworkAllocation {
    let request: CreateSandbox = serde_json::from_value(
        serde_json::json!({"profile":"controller-test","image":"fixture","ttl_seconds":600}),
    )
    .unwrap();
    let id = store
        .create_sandbox(&profile(), &request, &Uuid::new_v4().to_string())
        .await
        .unwrap()
        .sandbox
        .id;
    let reserved = store.reserve_network(id, Uuid::new_v4()).await.unwrap();
    if provision {
        store
            .begin_network_provisioning(id, reserved.generation, reserved.revision)
            .await
            .unwrap()
    } else {
        reserved
    }
}
#[tokio::test]
async fn probe_unknown_create_is_fenced_and_only_collected_original_scope_can_bind_native() {
    checked(|fixture| async move {
        use goldenhoop_egress::{HostProcessPlan, ProbePurpose};
        let store = fixture.open().await;
        let network = pre_native(&store, true).await;
        let id = network.sandbox_id;
        let probe = store
            .reserve_network_probe(
                id,
                network.generation,
                Uuid::new_v4(),
                &image(),
                ProbePurpose::Discover,
                Some(&"b".repeat(64)),
            )
            .await
            .unwrap();
        assert!(matches!(probe.plan, HostProcessPlan::Probe(_)));
        assert!(probe.plan.controller().is_err());
        assert!(
            store
                .reserve_network_controller(id, network.generation, Uuid::new_v4(), &image())
                .await
                .is_err()
        );
        let binding = NetworkNativeBinding {
            network_id: "b".repeat(64),
            allocation: Allocation {
                installation_id: store.installation_id(),
                sandbox_id: id,
                generation: network.generation,
                bridge: network.bridge.clone(),
                ifindex: 42,
            },
        };
        assert!(
            store
                .bind_native_network(
                    id,
                    network.generation,
                    network.token.unwrap(),
                    binding.clone()
                )
                .await
                .is_err()
        );
        let creating = store
            .begin_controller_create(id, probe.controller_generation, probe.revision)
            .await
            .unwrap();
        store.close().await;
        let reopened = fixture.open().await;
        let recovered = reopened
            .network_controller(id, probe.controller_generation)
            .await
            .unwrap();
        assert_eq!(recovered.create_token, creating.create_token);
        assert!(
            reopened
                .begin_controller_create(id, probe.controller_generation, recovered.revision)
                .await
                .is_err()
        );
        let collecting = reopened
            .begin_controller_collection(id, probe.controller_generation, recovered.revision)
            .await
            .unwrap();
        assert!(
            reopened
                .confirm_controller_absence(
                    id,
                    probe.controller_generation,
                    collecting.collection_token.unwrap(),
                    ControllerAbsence {
                        container_id: None,
                        creation_settled: true,
                        start_settled: true,
                        provider_absent: true,
                        observed_at: Utc::now()
                    }
                )
                .await
                .is_err()
        );
        let container = "c".repeat(64);
        let adopted = reopened
            .record_controller_created(
                id,
                probe.controller_generation,
                creating.create_token.unwrap(),
                &container,
            )
            .await
            .unwrap();
        assert_eq!(adopted.phase, ControllerPhase::Collecting);
        reopened
            .confirm_controller_absence(
                id,
                probe.controller_generation,
                adopted.collection_token.unwrap(),
                ControllerAbsence {
                    container_id: Some(container),
                    creation_settled: true,
                    start_settled: true,
                    provider_absent: true,
                    observed_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        let mut wrong = binding.clone();
        wrong.network_id = "d".repeat(64);
        assert!(
            reopened
                .bind_native_network(id, network.generation, network.token.unwrap(), wrong)
                .await
                .is_err()
        );
        let bound = reopened
            .bind_native_network(id, network.generation, network.token.unwrap(), binding)
            .await
            .unwrap();
        assert_eq!(bound.native.unwrap().allocation.ifindex, 42);
    })
    .await;
}
#[tokio::test]
async fn a_never_dispatched_network_can_collect_without_manufacturing_a_native_index() {
    checked(|fixture| async move {
        use goldenhoop_egress::{HostProcessPlan, ProbePurpose};
        let store = fixture.open().await;
        let network = pre_native(&store, false).await;
        let id = network.sandbox_id;
        store
            .set_desired(id, DesiredState::Terminated, "stop-before-native")
            .await
            .unwrap();
        let collecting = store
            .begin_network_collection(id, network.generation, network.revision)
            .await
            .unwrap();
        let reserved = store
            .reserve_network_probe(
                id,
                network.generation,
                Uuid::new_v4(),
                &image(),
                ProbePurpose::ObserveAbsence,
                None,
            )
            .await
            .unwrap();
        let HostProcessPlan::Probe(plan) = &reserved.plan else {
            panic!("expected absence probe")
        };
        assert!(plan.network_id.is_none() && plan.provisioning_token.is_none());
        assert!(reserved.network_id.is_none());
        let stopping = store
            .begin_controller_collection(id, reserved.controller_generation, reserved.revision)
            .await
            .unwrap();
        store
            .confirm_controller_absence(
                id,
                reserved.controller_generation,
                stopping.collection_token.unwrap(),
                ControllerAbsence {
                    container_id: None,
                    creation_settled: true,
                    start_settled: true,
                    provider_absent: true,
                    observed_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        let done = store
            .confirm_network_absence(
                id,
                network.generation,
                collecting.token.unwrap(),
                NetworkAbsence {
                    provisioning_settled: true,
                    endpoints_absent: true,
                    network_absent: true,
                    bridge_absent: true,
                    owned_tables_absent: true,
                    observed_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        assert_eq!(done.phase, NetworkPhase::Collected);
        assert!(done.native_binding().is_none());
    })
    .await;
}
async fn created(store: &Store, network: &NetworkAllocation, idchar: char) -> NetworkController {
    let reserved = reserve(store, network).await;
    let dispatch = store
        .begin_controller_create(
            network.sandbox_id,
            reserved.controller_generation,
            reserved.revision,
        )
        .await
        .unwrap();
    store
        .record_controller_created(
            network.sandbox_id,
            dispatch.controller_generation,
            dispatch.create_token.unwrap(),
            &idchar.to_string().repeat(64),
        )
        .await
        .unwrap()
}
fn absence(record: &NetworkController) -> ControllerAbsence {
    ControllerAbsence {
        container_id: record.container_id.clone(),
        creation_settled: true,
        start_settled: true,
        provider_absent: true,
        observed_at: Utc::now(),
    }
}
fn network_absence() -> NetworkAbsence {
    NetworkAbsence {
        provisioning_settled: true,
        endpoints_absent: true,
        network_absent: true,
        bridge_absent: true,
        owned_tables_absent: true,
        observed_at: Utc::now(),
    }
}
async fn collect(store: &Store, record: &NetworkController) -> NetworkController {
    let collecting = store
        .begin_controller_collection(
            record.sandbox_id,
            record.controller_generation,
            record.revision,
        )
        .await
        .unwrap();
    store
        .confirm_controller_absence(
            record.sandbox_id,
            record.controller_generation,
            collecting.collection_token.unwrap(),
            absence(&collecting),
        )
        .await
        .unwrap()
}
fn code<T: std::fmt::Debug>(value: Result<T, ApiError>, expected: ErrorCode) {
    assert_eq!(value.unwrap_err().code, expected);
}

#[tokio::test]
async fn create_and_start_dispatches_survive_close_with_exact_tokens_and_no_replay() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let network = allocation(&store, 100).await;
        let id = network.sandbox_id;
        let generation = Uuid::new_v4();
        let pin = image();
        let (a, b) = tokio::join!(
            store.reserve_network_controller(id, network.generation, generation, &pin),
            store.reserve_network_controller(id, network.generation, generation, &pin)
        );
        let reserved = a.unwrap();
        assert_eq!(reserved.revision, b.unwrap().revision);
        assert_eq!(reserved.plan.generation(), Some(generation));
        code(
            store
                .reserve_network_controller(id, network.generation, generation, "mutable:test")
                .await,
            ErrorCode::Conflict,
        );
        let (a, b) = tokio::join!(
            store.begin_controller_create(id, generation, 0),
            store.begin_controller_create(id, generation, 0)
        );
        assert_ne!(a.is_ok(), b.is_ok());
        let creating = a.or(b).unwrap();
        store.close().await;
        let reopened = fixture.open().await;
        let recovered = reopened.network_controller(id, generation).await.unwrap();
        assert_eq!(recovered.phase, ControllerPhase::Creating);
        assert_eq!(recovered.create_token, creating.create_token);
        assert!(recovered.container_id.is_none());
        assert_eq!(
            serde_json::to_value(&recovered.plan).unwrap(),
            serde_json::to_value(&reserved.plan).unwrap()
        );
        code(
            reopened
                .begin_controller_create(id, generation, recovered.revision)
                .await,
            ErrorCode::Conflict,
        );
        code(
            reopened
                .record_controller_created(id, generation, Uuid::new_v4(), &"b".repeat(64))
                .await,
            ErrorCode::Conflict,
        );
        let created = reopened
            .record_controller_created(
                id,
                generation,
                recovered.create_token.unwrap(),
                &"b".repeat(64),
            )
            .await
            .unwrap();
        let replay = reopened
            .record_controller_created(
                id,
                generation,
                recovered.create_token.unwrap(),
                &"b".repeat(64),
            )
            .await
            .unwrap();
        assert_eq!(replay.revision, created.revision);
        let starting = reopened
            .begin_controller_start(id, generation, created.revision)
            .await
            .unwrap();
        reopened.close().await;
        let store = fixture.open().await;
        let again = store.network_controller(id, generation).await.unwrap();
        assert_eq!(again.phase, ControllerPhase::Starting);
        assert_eq!(again.start_token, starting.start_token);
        code(
            store
                .begin_controller_start(id, generation, again.revision)
                .await,
            ErrorCode::Conflict,
        );
        code(
            store
                .record_controller_running(id, generation, Uuid::new_v4(), &"b".repeat(64))
                .await,
            ErrorCode::Conflict,
        );
        let running = store
            .record_controller_running(id, generation, again.start_token.unwrap(), &"b".repeat(64))
            .await
            .unwrap();
        assert_eq!(running.phase, ControllerPhase::Running);
        assert_eq!(
            store
                .record_controller_running(
                    id,
                    generation,
                    again.start_token.unwrap(),
                    &"b".repeat(64)
                )
                .await
                .unwrap()
                .revision,
            running.revision
        );
        let history = store
            .network_controller_history(id, generation, None, 128)
            .await
            .unwrap();
        assert_eq!(
            history.iter().map(|v| v.phase).collect::<Vec<_>>(),
            vec![
                ControllerPhase::Reserved,
                ControllerPhase::Creating,
                ControllerPhase::Created,
                ControllerPhase::Starting,
                ControllerPhase::Running
            ]
        );
        assert!(
            store
                .network_controller_history(Uuid::new_v4(), generation, None, 128)
                .await
                .is_err()
        );
        code(
            store
                .network_controller_history(id, generation, None, 0)
                .await,
            ErrorCode::InvalidRequest,
        );
    })
    .await;
}

#[tokio::test]
async fn unknown_creation_never_becomes_absence_and_late_acknowledgement_stays_collecting() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let network = allocation(&store, 100).await;
        let record = reserve(&store, &network).await;
        let id = record.sandbox_id;
        let g = record.controller_generation;
        let dispatch = store
            .begin_controller_create(id, g, record.revision)
            .await
            .unwrap();
        let collecting = store
            .begin_controller_collection(id, g, dispatch.revision)
            .await
            .unwrap();
        code(
            store
                .confirm_controller_absence(
                    id,
                    g,
                    collecting.collection_token.unwrap(),
                    absence(&collecting),
                )
                .await,
            ErrorCode::Conflict,
        );
        let late = store
            .record_controller_created(id, g, dispatch.create_token.unwrap(), &"b".repeat(64))
            .await
            .unwrap();
        assert_eq!(late.phase, ControllerPhase::Collecting);
        code(
            store.begin_controller_start(id, g, late.revision).await,
            ErrorCode::Conflict,
        );
        let done = store
            .confirm_controller_absence(id, g, late.collection_token.unwrap(), absence(&late))
            .await
            .unwrap();
        assert_eq!(done.phase, ControllerPhase::Collected);
        let replay = store
            .record_controller_created(id, g, dispatch.create_token.unwrap(), &"b".repeat(64))
            .await
            .unwrap();
        assert_eq!(replay.revision, done.revision);
        assert_eq!(replay.phase, ControllerPhase::Collected);
    })
    .await;
}

#[tokio::test]
async fn network_collection_fences_all_controllers_and_retains_cleanup_until_fresh_exact_absence() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let network = allocation(&store, 100).await;
        let record = created(&store, &network, 'b').await;
        let id = network.sandbox_id;
        let g = record.controller_generation;
        let active = store
            .begin_controller_start(id, g, record.revision)
            .await
            .unwrap();
        let network = store
            .begin_network_collection(id, network.generation, network.revision)
            .await
            .unwrap();
        let collecting = store.network_controller(id, g).await.unwrap();
        assert_eq!(collecting.phase, ControllerPhase::Collecting);
        assert_eq!(collecting.start_token, active.start_token);
        code(
            store
                .record_controller_running(id, g, active.start_token.unwrap(), &"b".repeat(64))
                .await,
            ErrorCode::Conflict,
        );
        code(
            store
                .confirm_network_absence(
                    id,
                    network.generation,
                    network.token.unwrap(),
                    network_absence(),
                )
                .await,
            ErrorCode::InvalidState,
        );
        let good = absence(&collecting);
        let mut variants = Vec::new();
        let mut bad = good.clone();
        bad.creation_settled = false;
        variants.push(bad);
        let mut bad = good.clone();
        bad.start_settled = false;
        variants.push(bad);
        let mut bad = good.clone();
        bad.provider_absent = false;
        variants.push(bad);
        let mut bad = good.clone();
        bad.container_id = Some("c".repeat(64));
        variants.push(bad);
        let mut bad = good.clone();
        bad.observed_at -= Duration::seconds(10);
        variants.push(bad);
        let mut bad = good.clone();
        bad.observed_at += Duration::seconds(10);
        variants.push(bad);
        for bad in variants {
            code(
                store
                    .confirm_controller_absence(id, g, collecting.collection_token.unwrap(), bad)
                    .await,
                ErrorCode::Conflict,
            );
        }
        let done = store
            .confirm_controller_absence(id, g, collecting.collection_token.unwrap(), good.clone())
            .await
            .unwrap();
        assert_eq!(
            store
                .confirm_controller_absence(id, g, collecting.collection_token.unwrap(), good)
                .await
                .unwrap()
                .revision,
            done.revision
        );
        store
            .confirm_network_absence(
                id,
                network.generation,
                network.token.unwrap(),
                network_absence(),
            )
            .await
            .unwrap();
        let mut sandbox = store.sandbox(id).await.unwrap();
        sandbox.sandbox.state = SandboxState::Failed;
        sandbox.sandbox.cleanup = CleanupState::Complete;
        store.observe(sandbox).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn a_new_epoch_requires_old_collection_and_cannot_reuse_old_dispatches_or_physical_ids() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let network = allocation(&store, 100).await;
        let first = created(&store, &network, 'b').await;
        assert!(
            store
                .reserve_network_controller(
                    network.sandbox_id,
                    network.generation,
                    Uuid::new_v4(),
                    &image()
                )
                .await
                .is_err()
        );
        let done = collect(&store, &first).await;
        let replay = store
            .reserve_network_controller(
                first.sandbox_id,
                network.generation,
                first.controller_generation,
                &image(),
            )
            .await
            .unwrap();
        assert_eq!(replay.phase, ControllerPhase::Collected);
        code(
            store
                .begin_controller_create(
                    first.sandbox_id,
                    first.controller_generation,
                    replay.revision,
                )
                .await,
            ErrorCode::Conflict,
        );
        let second = reserve(&store, &network).await;
        assert_ne!(done.plan.name(), second.plan.name());
        assert_eq!(
            done.plan.controller().unwrap().native.allocation.owner(),
            second.plan.controller().unwrap().native.allocation.owner()
        );
        let dispatch = store
            .begin_controller_create(
                second.sandbox_id,
                second.controller_generation,
                second.revision,
            )
            .await
            .unwrap();
        code(
            store
                .record_controller_created(
                    second.sandbox_id,
                    second.controller_generation,
                    first.create_token.unwrap(),
                    &"c".repeat(64),
                )
                .await,
            ErrorCode::Conflict,
        );
        code(
            store
                .record_controller_created(
                    second.sandbox_id,
                    second.controller_generation,
                    dispatch.create_token.unwrap(),
                    &"b".repeat(64),
                )
                .await,
            ErrorCode::Conflict,
        );
        store
            .record_controller_created(
                second.sandbox_id,
                second.controller_generation,
                dispatch.create_token.unwrap(),
                &"c".repeat(64),
            )
            .await
            .unwrap();
    })
    .await;
}

#[tokio::test]
async fn fresh_controller_residue_atomically_revokes_controller_network_and_sandbox_cleanup() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let network = allocation(&store, 100).await;
        let first = created(&store, &network, 'b').await;
        let done = collect(&store, &first).await;
        let id = network.sandbox_id;
        let network = store
            .begin_network_collection(id, network.generation, network.revision)
            .await
            .unwrap();
        store
            .confirm_network_absence(
                id,
                network.generation,
                network.token.unwrap(),
                network_absence(),
            )
            .await
            .unwrap();
        let mut sandbox = store.sandbox(id).await.unwrap();
        sandbox.sandbox.state = SandboxState::Failed;
        sandbox.sandbox.cleanup = CleanupState::Complete;
        store.observe(sandbox).await.unwrap();
        code(
            store
                .reopen_controller_collection(
                    id,
                    first.controller_generation,
                    &"b".repeat(64),
                    done.absence.as_ref().unwrap().observed_at,
                )
                .await,
            ErrorCode::Conflict,
        );
        let reopened = store
            .reopen_controller_collection(
                id,
                first.controller_generation,
                &"b".repeat(64),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(reopened.phase, ControllerPhase::Collecting);
        assert!(reopened.absence.is_none());
        assert_eq!(
            store.network_allocation(id).await.unwrap().phase,
            NetworkPhase::Unknown
        );
        let sandbox = store.sandbox(id).await.unwrap();
        assert_eq!(sandbox.sandbox.state, SandboxState::Unknown);
        assert_eq!(sandbox.sandbox.cleanup, CleanupState::Unknown);
        assert_eq!(sandbox.sandbox.desired_state, DesiredState::Terminated);
        assert!(
            store
                .work()
                .await
                .unwrap()
                .iter()
                .any(|v| v.sandbox.id == id)
        );
        code(
            store
                .confirm_network_absence(
                    id,
                    network.generation,
                    network.token.unwrap(),
                    network_absence(),
                )
                .await,
            ErrorCode::Conflict,
        );
    })
    .await;
}

#[tokio::test]
async fn schema_seven_upgrade_preserves_native_history_bytes_and_existing_operation_identity() {
    checked(|fixture|async move {
        let store=fixture.open().await;let network=allocation(&store,100).await;let id=network.sandbox_id;let operation=store.sandbox(id).await.unwrap().create_operation;let installation=store.installation_id();store.close().await;
        let options=SqliteConnectOptions::new().filename(&fixture.path);let mut connection=SqliteConnection::connect_with(&options).await.unwrap();
        let result=async {
            sqlx::raw_sql("DROP TABLE network_policy_events;DROP TABLE network_policies;DROP TABLE network_controller_events;DROP TABLE network_controllers;UPDATE meta SET value='7' WHERE key='schema_version'").execute(&mut connection).await?;
            let current:String=sqlx::query_scalar("SELECT payload FROM network_allocations WHERE sandbox_id=?").bind(id.to_string()).fetch_one(&mut connection).await?;
            let history:Vec<String>=sqlx::query_scalar("SELECT payload FROM network_allocation_events WHERE sandbox_id=? ORDER BY revision").bind(id.to_string()).fetch_all(&mut connection).await?;
            Ok::<_,sqlx::Error>((current,history))
        }.await;connection.close().await.unwrap();let before=result.unwrap();
        let upgraded=fixture.open().await;assert_eq!(upgraded.installation_id(),installation);assert_eq!(upgraded.sandbox(id).await.unwrap().create_operation,operation);assert!(upgraded.active_network_controller(id).await.unwrap().is_none());
        let mut connection=SqliteConnection::connect_with(&options).await.unwrap();let result=async {
            let version:String=sqlx::query_scalar("SELECT value FROM meta WHERE key='schema_version'").fetch_one(&mut connection).await?;
            let current:String=sqlx::query_scalar("SELECT payload FROM network_allocations WHERE sandbox_id=?").bind(id.to_string()).fetch_one(&mut connection).await?;
            let history:Vec<String>=sqlx::query_scalar("SELECT payload FROM network_allocation_events WHERE sandbox_id=? ORDER BY revision").bind(id.to_string()).fetch_all(&mut connection).await?;
            Ok::<_,sqlx::Error>((version,current,history))
        }.await;connection.close().await.unwrap();let after=result.unwrap();assert_eq!(after.0,"11");assert_eq!((after.1,after.2),before);
        reserve(&upgraded,&network).await;
    }).await;
}

#[tokio::test]
async fn missing_native_checkpoint_cancellation_and_expired_metadata_refuse_new_dispatch() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let request: CreateSandbox = serde_json::from_value(
            serde_json::json!({"profile":"controller-test","image":"fixture","ttl_seconds":600}),
        )
        .unwrap();
        let id = store
            .create_sandbox(&profile(), &request, "missing-native")
            .await
            .unwrap()
            .sandbox
            .id;
        let reserved = store.reserve_network(id, Uuid::new_v4()).await.unwrap();
        let network = store
            .begin_network_provisioning(id, reserved.generation, 0)
            .await
            .unwrap();
        assert!(
            store
                .reserve_network_controller(id, network.generation, Uuid::new_v4(), &image())
                .await
                .is_err()
        );
        assert!(store.active_network_controller(id).await.unwrap().is_none());
        let native = NetworkNativeBinding {
            network_id: "a".repeat(64),
            allocation: Allocation {
                installation_id: store.installation_id(),
                sandbox_id: id,
                generation: network.generation,
                bridge: network.bridge.clone(),
                ifindex: 100,
            },
        };
        let network = store
            .bind_native_network(id, network.generation, network.token.unwrap(), native)
            .await
            .unwrap();
        code(
            store
                .reserve_network_controller(id, network.generation, Uuid::new_v4(), "mutable:test")
                .await,
            ErrorCode::InvalidRequest,
        );
        let controller = reserve(&store, &network).await;
        store
            .set_desired(id, DesiredState::Terminated, "cancel-before-create")
            .await
            .unwrap();
        code(
            store
                .begin_controller_create(id, controller.controller_generation, controller.revision)
                .await,
            ErrorCode::Conflict,
        );
        let collected = collect(&store, &controller).await;
        assert!(collected.container_id.is_none());
        assert!(collected.create_token.is_none());
        let live = allocation(&store, 101).await;
        let controller = created(&store, &live, 'c').await;
        store
            .set_desired(
                live.sandbox_id,
                DesiredState::Terminated,
                "cancel-before-start",
            )
            .await
            .unwrap();
        code(
            store
                .begin_controller_start(
                    live.sandbox_id,
                    controller.controller_generation,
                    controller.revision,
                )
                .await,
            ErrorCode::Conflict,
        );
        let expired = allocation(&store, 102).await;
        let mut sandbox = store.sandbox(expired.sandbox_id).await.unwrap().sandbox;
        // Synthetic fixture time, preserving the sandbox's lifetime. No wall-
        // clock expiry or provider collection is claimed by this metadata test.
        sandbox.created_at -= Duration::seconds(601);
        sandbox.expires_at -= Duration::seconds(601);
        sandbox.observed_at = sandbox.observed_at.map(|t| t - Duration::seconds(601));
        let mut connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&fixture.path))
                .await
                .unwrap();
        let result = sqlx::query("UPDATE sandboxes SET payload=? WHERE id=?")
            .bind(serde_json::to_string(&sandbox).unwrap())
            .bind(expired.sandbox_id.to_string())
            .execute(&mut connection)
            .await;
        connection.close().await.unwrap();
        result.unwrap();
        code(
            store
                .reserve_network_controller(
                    expired.sandbox_id,
                    expired.generation,
                    Uuid::new_v4(),
                    &image(),
                )
                .await,
            ErrorCode::DeadlineExceeded,
        );
        assert!(
            store
                .active_network_controller(expired.sandbox_id)
                .await
                .unwrap()
                .is_none()
        );
    })
    .await;
}

#[tokio::test]
async fn collector_uses_original_identity_after_expiry_only_inside_network_collection() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let network = allocation(&store, 100).await;
        let id = network.sandbox_id;
        assert!(
            store
                .reserve_network_collector(id, network.generation, Uuid::new_v4(), &image())
                .await
                .is_err()
        );
        let mut sandbox = store.sandbox(id).await.unwrap().sandbox;
        sandbox.created_at -= Duration::seconds(601);
        sandbox.expires_at -= Duration::seconds(601);
        sandbox.observed_at = sandbox.observed_at.map(|t| t - Duration::seconds(601));
        let mut connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&fixture.path))
                .await
                .unwrap();
        let result = sqlx::query("UPDATE sandboxes SET payload=? WHERE id=?")
            .bind(serde_json::to_string(&sandbox).unwrap())
            .bind(id.to_string())
            .execute(&mut connection)
            .await;
        connection.close().await.unwrap();
        result.unwrap();
        let collecting = store
            .begin_network_collection(id, network.generation, network.revision)
            .await
            .unwrap();
        let reserved = store
            .reserve_network_collector(id, network.generation, Uuid::new_v4(), &image())
            .await
            .unwrap();
        assert_eq!(
            reserved.plan.controller().unwrap().purpose,
            goldenhoop_egress::ControllerPurpose::Collect
        );
        assert_eq!(
            reserved
                .plan
                .controller()
                .unwrap()
                .native
                .provisioning_token,
            network.token.unwrap()
        );
        assert_ne!(
            Some(
                reserved
                    .plan
                    .controller()
                    .unwrap()
                    .native
                    .provisioning_token
            ),
            collecting.token
        );
        assert_eq!(
            reserved.plan.controller().unwrap().native.expires_at,
            sandbox.expires_at
        );
        assert!(
            reserved
                .plan
                .controller()
                .unwrap()
                .native
                .validate_at(Utc::now())
                .is_err()
        );
        reserved.plan.validate_dispatch_at(Utc::now()).unwrap();
        let creating = store
            .begin_controller_create(id, reserved.controller_generation, reserved.revision)
            .await
            .unwrap();
        let created = store
            .record_controller_created(
                id,
                creating.controller_generation,
                creating.create_token.unwrap(),
                &"b".repeat(64),
            )
            .await
            .unwrap();
        let starting = store
            .begin_controller_start(id, created.controller_generation, created.revision)
            .await
            .unwrap();
        let running = store
            .record_controller_running(
                id,
                starting.controller_generation,
                starting.start_token.unwrap(),
                &"b".repeat(64),
            )
            .await
            .unwrap();
        assert_eq!(running.phase, ControllerPhase::Running);
        assert!(
            store
                .reserve_network_controller(id, network.generation, Uuid::new_v4(), &image())
                .await
                .is_err()
        );
        collect(&store, &running).await;
    })
    .await;
}

#[tokio::test]
async fn schema_eight_controller_payload_and_history_bytes_survive_purpose_upgrade() {
    checked(|fixture|async move {
        let store=fixture.open().await;let network=allocation(&store,100).await;let reserved=reserve(&store,&network).await;
        let creating=store.begin_controller_create(network.sandbox_id,reserved.controller_generation,reserved.revision).await.unwrap();store.close().await;
        let options=SqliteConnectOptions::new().filename(&fixture.path);let mut connection=SqliteConnection::connect_with(&options).await.unwrap();
        let before=async {
            sqlx::raw_sql("DROP TABLE network_policy_events;DROP TABLE network_policies;UPDATE meta SET value='8' WHERE key='schema_version'").execute(&mut connection).await?;
            let payload:String=sqlx::query_scalar("SELECT payload FROM network_controllers WHERE controller_generation=?").bind(creating.controller_generation.to_string()).fetch_one(&mut connection).await?;
            let history:Vec<String>=sqlx::query_scalar("SELECT payload FROM network_controller_events WHERE controller_generation=? ORDER BY revision").bind(creating.controller_generation.to_string()).fetch_all(&mut connection).await?;
            Ok::<_,sqlx::Error>((payload,history))
        }.await;connection.close().await.unwrap();let before=before.unwrap();assert!(!serde_json::from_str::<serde_json::Value>(&before.0).unwrap()["plan"].as_object().unwrap().contains_key("purpose"));
        let upgraded=fixture.open().await;let actual=upgraded.network_controller(network.sandbox_id,creating.controller_generation).await.unwrap();assert_eq!(actual.phase,ControllerPhase::Creating);assert_eq!(actual.create_token,creating.create_token);assert_eq!(actual.plan.controller().unwrap().purpose,goldenhoop_egress::ControllerPurpose::Enforce);
        let mut connection=SqliteConnection::connect_with(&options).await.unwrap();let after=async {
            let version:String=sqlx::query_scalar("SELECT value FROM meta WHERE key='schema_version'").fetch_one(&mut connection).await?;
            let payload:String=sqlx::query_scalar("SELECT payload FROM network_controllers WHERE controller_generation=?").bind(creating.controller_generation.to_string()).fetch_one(&mut connection).await?;
            let history:Vec<String>=sqlx::query_scalar("SELECT payload FROM network_controller_events WHERE controller_generation=? ORDER BY revision").bind(creating.controller_generation.to_string()).fetch_all(&mut connection).await?;
            Ok::<_,sqlx::Error>((version,payload,history))
        }.await;connection.close().await.unwrap();let after=after.unwrap();assert_eq!(after.0,"11");assert_eq!((after.1,after.2),before);
        assert!(upgraded.begin_controller_create(network.sandbox_id,creating.controller_generation,actual.revision).await.is_err());
    }).await;
}

#[tokio::test]
async fn schema_nine_native_enforcement_and_collection_dispatches_keep_exact_bytes() {
    checked(|fixture| async move {
        let store = fixture.open().await;
        let first = allocation(&store, 100).await;
        let enforcing = reserve(&store, &first).await;
        let second = allocation(&store, 101).await;
        store
            .set_desired(second.sandbox_id, DesiredState::Terminated, "collect-v9")
            .await
            .unwrap();
        store
            .begin_network_collection(second.sandbox_id, second.generation, second.revision)
            .await
            .unwrap();
        let collecting = store
            .reserve_network_collector(
                second.sandbox_id,
                second.generation,
                Uuid::new_v4(),
                &image(),
            )
            .await
            .unwrap();
        let mut dispatched = Vec::new();
        for record in [enforcing, collecting] {
            dispatched.push(
                store
                    .begin_controller_create(
                        record.sandbox_id,
                        record.controller_generation,
                        record.revision,
                    )
                    .await
                    .unwrap(),
            );
        }
        store.close().await;
        let options = SqliteConnectOptions::new().filename(&fixture.path);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::raw_sql("DROP TABLE network_policy_events;DROP TABLE network_policies;UPDATE meta SET value='9' WHERE key='schema_version'")
            .execute(&mut connection)
            .await
            .unwrap();
        async fn snapshot(connection: &mut SqliteConnection) -> Vec<String> {
            sqlx::query_scalar("SELECT payload FROM network_controllers ORDER BY controller_generation")
                .fetch_all(&mut *connection).await.unwrap().into_iter().chain(
                    sqlx::query_scalar::<_, String>("SELECT payload FROM network_controller_events ORDER BY controller_generation,revision")
                        .fetch_all(connection).await.unwrap()
                ).collect()
        }
        let before = snapshot(&mut connection).await;
        connection.close().await.unwrap();
        let upgraded = fixture.open().await;
        for original in dispatched {
            let current = upgraded
                .network_controller(original.sandbox_id, original.controller_generation)
                .await
                .unwrap();
            assert_eq!(current.create_token, original.create_token);
            assert_eq!(current.phase, ControllerPhase::Creating);
            assert_eq!(
                serde_json::to_value(current.plan.controller().unwrap()).unwrap(),
                serde_json::to_value(original.plan.controller().unwrap()).unwrap()
            );
            assert!(
                upgraded
                    .begin_controller_create(current.sandbox_id, current.controller_generation, current.revision)
                    .await
                    .is_err()
            );
        }
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        let version: String = sqlx::query_scalar("SELECT value FROM meta WHERE key='schema_version'")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(version, "11");
        assert_eq!(snapshot(&mut connection).await, before);
        connection.close().await.unwrap();
    })
    .await;
}
