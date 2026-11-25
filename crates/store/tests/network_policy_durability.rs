//! Real file-backed ownership/CAS/restart transactions. Native receipts here
//! are synthetic; they cannot establish an actual worker-held live lease.
use chrono::Utc;
use futures_util::FutureExt;
use goldenhoop_egress::{Allocation, Config, EffectivePolicyReceipt, ProtectedBindingReceipt};
use goldenhoop_protocol::*;
use goldenhoop_runtime::RuntimeHandle;
use goldenhoop_store::*;
use std::{future::Future, panic::AssertUnwindSafe, path::PathBuf};
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
fn config(allow: bool) -> Config {
    serde_json::from_value(serde_json::json!({"policies":[{"default_action":"deny","rules":if allow{serde_json::json!([{"destination":"93.184.216.34","ports":[443],"action":"allow"}])}else{serde_json::json!([])}}]})).unwrap()
}
async fn fixture(store: &Store) -> (NetworkPolicyControl, WorkerRegistration) {
    let profile:RuntimeProfile=serde_json::from_value(serde_json::json!({"id":"policy-test","placement":"local","isolation":"gvisor","availability":"available","capabilities":["commands","files","network_isolation"],"max_resources":{"cpu_millis":16000,"memory_bytes":34359738368_u64,"pids":4096},"max_ttl_seconds":86400})).unwrap();
    let request: CreateSandbox = serde_json::from_value(
        serde_json::json!({"profile":"policy-test","image":"fixture","ttl_seconds":600}),
    )
    .unwrap();
    let id = store
        .create_sandbox(&profile, &request, &Uuid::new_v4().to_string())
        .await
        .unwrap()
        .sandbox
        .id;
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
        ifindex: 30,
    };
    let checkpoint:ProtectedBindingReceipt=serde_json::from_value(serde_json::json!({"allocation":allocation,"source":{"endpoint":{"port":"veth31","ifindex":31,"mac":"02:00:00:00:00:02","ipv4":"10.42.0.2","ipv6":"fd42::2"},"gateway_mac":"02:00:00:00:00:01","gateway4":"10.42.0.1","gateway6":"fd42::1"},"destinations":{"scope":{"host_addresses":["10.42.0.1","fd42::1"],"control_addresses":[],"private_exceptions":[]},"dns":[{"address":"10.42.0.1","port":40000},{"address":"fd42::1","port":40001}]},"revision":3,"expires_at":store.sandbox(id).await.unwrap().sandbox.expires_at,"observed_at":Utc::now()})).unwrap();
    checkpoint.validate().unwrap();
    store
        .bind_native_network(
            id,
            network.generation,
            network.token.unwrap(),
            NetworkNativeBinding {
                network_id: "a".repeat(64),
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
                network_id: "a".repeat(64),
                allocation,
                source: checkpoint.source.clone(),
                destinations: checkpoint.destinations.clone(),
            },
        )
        .await
        .unwrap();
    let mut sandbox = store.sandbox(id).await.unwrap();
    sandbox.sandbox.state = SandboxState::Starting;
    sandbox.sandbox.cleanup = CleanupState::Pending;
    sandbox.handle = Some(RuntimeHandle {
        sandbox_id: id,
        profile: "policy-test".into(),
        backend_ref: "b".repeat(64),
    });
    store.observe(sandbox).await.unwrap();
    let intent = store
        .stage_network_policy(
            id,
            network.generation,
            checkpoint,
            "8.8.8.8:53".parse().unwrap(),
            config(true),
        )
        .await
        .unwrap();
    let worker = WorkerRegistration {
        id: Uuid::new_v4(),
        endpoint: "http://127.0.0.1:1".into(),
        token: "test-only".into(),
        heartbeat: Utc::now(),
        profiles: vec![profile],
    };
    store.register_worker(&worker).await.unwrap();
    (intent, worker)
}
async fn controller(store: &Store, intent: &NetworkPolicyControl) -> NetworkController {
    let reserved = store
        .reserve_network_controller(
            intent.sandbox_id,
            intent.allocation_generation,
            Uuid::new_v4(),
            &format!("sha256:{}", "c".repeat(64)),
        )
        .await
        .unwrap();
    let creating = store
        .begin_controller_create(
            intent.sandbox_id,
            reserved.controller_generation,
            reserved.revision,
        )
        .await
        .unwrap();
    let physical_id = reserved
        .controller_generation
        .simple()
        .to_string()
        .repeat(2);
    let created = store
        .record_controller_created(
            intent.sandbox_id,
            reserved.controller_generation,
            creating.create_token.unwrap(),
            &physical_id,
        )
        .await
        .unwrap();
    let starting = store
        .begin_controller_start(
            intent.sandbox_id,
            reserved.controller_generation,
            created.revision,
        )
        .await
        .unwrap();
    store
        .record_controller_running(
            intent.sandbox_id,
            reserved.controller_generation,
            starting.start_token.unwrap(),
            &physical_id,
        )
        .await
        .unwrap()
}
fn receipt(intent: &NetworkPolicyControl) -> EffectivePolicyReceipt {
    let mut binding = intent.checkpoint.clone();
    binding.revision += 2;
    binding.observed_at = Utc::now();
    EffectivePolicyReceipt {
        binding,
        config_sha256: intent.config_sha256.clone(),
        native_sha256: "e".repeat(64),
        lease_remaining_milliseconds: 8000,
    }
}
#[tokio::test]
async fn changed_desired_policy_fences_running_and_rejects_inflight_old_ack() {
    checked(|store, _| async move {
        let (intent, worker) = fixture(&store).await;
        let id = intent.sandbox_id;
        let runtime = store.sandbox(id).await.unwrap().handle.unwrap();
        let controller = controller(&store, &intent).await;
        let claimed = store
            .claim_network_policy(
                id,
                intent.revision,
                worker.id,
                controller.controller_generation,
            )
            .await
            .unwrap();
        let owner = claimed.owner.as_ref().unwrap();
        let applying = store
            .begin_network_policy_apply(id, claimed.revision, owner)
            .await
            .unwrap();
        let active = store
            .confirm_network_policy(
                id,
                applying.revision,
                owner,
                applying.attempt.unwrap(),
                receipt(&applying),
            )
            .await
            .unwrap();
        let mut sandbox = store.sandbox(id).await.unwrap();
        sandbox.sandbox.state = SandboxState::Running;
        store.observe(sandbox).await.unwrap();
        let inflight = store
            .begin_network_policy_apply(id, active.revision, owner)
            .await
            .unwrap();
        let changed = store
            .update_network_policy(id, intent.allocation_generation, 0, config(false))
            .await
            .unwrap();
        assert_eq!(changed.phase, NetworkPolicyPhase::Pending);
        assert_eq!(changed.desired_revision, 1);
        assert!(changed.observation.is_none());
        assert_eq!(
            store
                .confirm_network_policy(
                    id,
                    inflight.revision,
                    owner,
                    inflight.attempt.unwrap(),
                    receipt(&inflight)
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert!(
            store
                .update_network_policy(id, intent.allocation_generation, 0, config(true))
                .await
                .is_err()
        );
        let sandbox = store.sandbox(id).await.unwrap();
        assert_eq!(sandbox.sandbox.state, SandboxState::Unknown);
        assert!(sandbox.ever_running);
        assert_eq!(sandbox.handle.unwrap().backend_ref, runtime.backend_ref);
        let new = store
            .begin_network_policy_apply(id, changed.revision, owner)
            .await
            .unwrap();
        assert!(
            store
                .confirm_network_policy(
                    id,
                    new.revision,
                    owner,
                    new.attempt.unwrap(),
                    receipt(&inflight)
                )
                .await
                .is_err()
        );
        let final_policy = store
            .confirm_network_policy(id, new.revision, owner, new.attempt.unwrap(), receipt(&new))
            .await
            .unwrap();
        assert_eq!(final_policy.phase, NetworkPolicyPhase::Active);
    })
    .await;
}
#[tokio::test]
async fn reopen_keeps_historical_ack_but_new_owner_requires_old_process_collection() {
    checked(|store, path| async move {
        let (intent, worker) = fixture(&store).await;
        let id = intent.sandbox_id;
        let current = controller(&store, &intent).await;
        let claimed = store
            .claim_network_policy(
                id,
                intent.revision,
                worker.id,
                current.controller_generation,
            )
            .await
            .unwrap();
        let owner = claimed.owner.clone().unwrap();
        let applying = store
            .begin_network_policy_apply(id, claimed.revision, &owner)
            .await
            .unwrap();
        let active = store
            .confirm_network_policy(
                id,
                applying.revision,
                &owner,
                applying.attempt.unwrap(),
                receipt(&applying),
            )
            .await
            .unwrap();
        let mut running = store.sandbox(id).await.unwrap();
        running.sandbox.state = SandboxState::Running;
        let original_handle = running.handle.clone().unwrap();
        store.observe(running).await.unwrap();
        store.close().await;
        let reopened = Store::open(&path).await.unwrap();
        let result = AssertUnwindSafe(async {
            let old = reopened.network_policy(id).await.unwrap();
            assert_eq!(old.revision, active.revision);
            assert_eq!(old.owner.as_ref(), Some(&owner));
            assert_eq!(old.phase, NetworkPolicyPhase::Active);
            let mut heartbeat = worker.clone();
            heartbeat.heartbeat = Utc::now();
            reopened.register_worker(&heartbeat).await.unwrap();
            let still_active = reopened.network_policy(id).await.unwrap();
            assert_eq!(still_active.revision, old.revision);
            assert_eq!(still_active.phase, NetworkPolicyPhase::Active);
            assert_eq!(
                reopened.sandbox(id).await.unwrap().sandbox.state,
                SandboxState::Running
            );
            let mut replacement = worker.clone();
            replacement.id = Uuid::new_v4();
            replacement.heartbeat = Utc::now();
            reopened.register_worker(&replacement).await.unwrap();
            let fenced = reopened.network_policy(id).await.unwrap();
            assert_eq!(fenced.phase, NetworkPolicyPhase::Fenced);
            assert!(fenced.observation.is_none());
            assert_eq!(fenced.owner.as_ref(), Some(&owner));
            assert_eq!(reopened.worker().await.unwrap().id, replacement.id);
            let sandbox = reopened.sandbox(id).await.unwrap();
            assert_eq!(sandbox.sandbox.state, SandboxState::Unknown);
            assert!(sandbox.ever_running);
            assert_eq!(
                sandbox.handle.unwrap().backend_ref,
                original_handle.backend_ref
            );
            assert!(
                reopened
                    .begin_network_policy_apply(id, old.revision, &owner)
                    .await
                    .is_err()
            );
            assert!(
                reopened
                    .claim_network_policy(
                        id,
                        old.revision,
                        replacement.id,
                        current.controller_generation
                    )
                    .await
                    .is_err()
            );
            reopened.fence_network_policy(id, &owner).await.unwrap();
            let collecting = reopened
                .begin_controller_collection(id, current.controller_generation, current.revision)
                .await
                .unwrap();
            reopened
                .confirm_controller_absence(
                    id,
                    current.controller_generation,
                    collecting.collection_token.unwrap(),
                    ControllerAbsence {
                        container_id: current.container_id.clone(),
                        creation_settled: true,
                        start_settled: true,
                        provider_absent: true,
                        observed_at: Utc::now(),
                    },
                )
                .await
                .unwrap();
            let next = controller(&reopened, &old).await;
            let fresh = reopened.network_policy(id).await.unwrap();
            let claimed = reopened
                .claim_network_policy(
                    id,
                    fresh.revision,
                    replacement.id,
                    next.controller_generation,
                )
                .await
                .unwrap();
            assert_eq!(claimed.phase, NetworkPolicyPhase::Recovering);
            assert!(claimed.observation.is_none());
            assert_ne!(claimed.owner.as_ref().unwrap().token, owner.token);
            assert!(
                reopened
                    .begin_network_policy_apply(id, claimed.revision, &owner)
                    .await
                    .is_err()
            );
        })
        .catch_unwind()
        .await;
        reopened.close().await;
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    })
    .await;
}
