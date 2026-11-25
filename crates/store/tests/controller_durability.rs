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
        assert_eq!(reserved.plan.controller_generation, Some(generation));
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
            done.plan.native.allocation.owner(),
            second.plan.native.allocation.owner()
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
            sqlx::raw_sql("DROP TABLE network_controller_events;DROP TABLE network_controllers;UPDATE meta SET value='7' WHERE key='schema_version'").execute(&mut connection).await?;
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
        }.await;connection.close().await.unwrap();let after=result.unwrap();assert_eq!(after.0,"8");assert_eq!((after.1,after.2),before);
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
