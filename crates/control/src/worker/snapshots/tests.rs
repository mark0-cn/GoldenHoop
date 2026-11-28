//! Real SQLite, mutex and HTTP tests; backend/VM observations are synthetic.
use super::*;
use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use futures_util::FutureExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    panic::AssertUnwindSafe,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::Notify;
use tower::ServiceExt;

const TOKEN: &str = "synthetic-snapshot-worker-token-0123456789abcdef";
const PENDING: usize = 0;
const READY: usize = 1;
const FAILED: usize = 2;
const REFUSED: usize = 3;

fn profile() -> RuntimeProfile {
    RuntimeProfile {
        id: "snapshot-worker-fixture".into(),
        placement: Placement::Local,
        isolation: Isolation::Firecracker,
        availability: Availability::Available,
        capabilities: BTreeSet::from([
            Capability::Commands,
            Capability::Files,
            Capability::Pause,
            Capability::NetworkIsolation,
            Capability::MemorySnapshot,
        ]),
        code_languages: Default::default(),
        max_resources: ResourceLimits {
            cpu_millis: 4000,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            pids: 1024,
        },
        max_ttl_seconds: 3600,
        reason: None,
    }
}
fn intent() -> CreateSnapshot {
    CreateSnapshot {
        kind: SnapshotKind::MemoryAndDisk,
    }
}
fn failure() -> ApiError {
    ApiError::new(ErrorCode::BackendUnavailable, "synthetic backend failure")
}

#[derive(Default)]
struct Backend {
    captures: AtomicUsize,
    inspections: AtomicUsize,
    collections: AtomicUsize,
    removals: AtomicUsize,
    starts: AtomicUsize,
    state: AtomicUsize,
    unsupported: AtomicBool,
    lose_reply: AtomicBool,
    remove_fails: AtomicBool,
    collect_fails: AtomicBool,
    wrong_source: AtomicBool,
    removed: AtomicBool,
    hold_rpc: AtomicBool,
    entered_rpc: Notify,
    release_rpc: Notify,
    rpc_finished: AtomicBool,
}
impl Backend {
    fn observation(&self, request: &MemoryCaptureRequest) -> MemoryCaptureObservation {
        let mut source = request.handle.clone();
        if self.wrong_source.load(Ordering::SeqCst) {
            source.backend_ref.push_str("-other-generation");
        }
        let state = match self.state.load(Ordering::SeqCst) {
            READY => MemoryCaptureState::Ready {
                manifest: Box::new(SnapshotManifest {
                    format_version: 1,
                    id: request.id,
                    source_sandbox_id: request.source.id,
                    kind: SnapshotKind::MemoryAndDisk,
                    driver: request.handle.profile.clone(),
                    architecture: "x86_64".into(),
                    image_digest: request.source.image.clone(),
                    objects: BTreeMap::from([
                        ("state".into(), format!("sha256:{}", "a".repeat(64))),
                        ("memory".into(), format!("sha256:{}", "b".repeat(64))),
                        ("disk".into(), format!("sha256:{}", "c".repeat(64))),
                    ]),
                    runtime_version: "synthetic".into(),
                    created_at: request.created_at,
                }),
                reference: serde_json::json!({"capture":request.id,"private_host_path":"/synthetic/private-reference"}),
            },
            FAILED => MemoryCaptureState::Failed(failure()),
            REFUSED => MemoryCaptureState::Refused {
                reason: ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "synthetic durable pre-reservation refusal",
                ),
                receipt: serde_json::json!({"capture":request.id,"source":request.handle.backend_ref,"private_receipt":"synthetic-permanently-closed-id"}),
            },
            PENDING => MemoryCaptureState::Pending,
            _ => unreachable!("unknown synthetic capture scenario"),
        };
        MemoryCaptureObservation {
            id: request.id,
            source,
            state,
        }
    }
}
#[async_trait]
impl RuntimeDriver for Backend {
    fn supports_memory_capture(&self) -> bool {
        !self.unsupported.load(Ordering::SeqCst)
    }
    async fn capture_memory(
        &self,
        request: &MemoryCaptureRequest,
    ) -> Result<MemoryCaptureObservation, ApiError> {
        self.captures.fetch_add(1, Ordering::SeqCst);
        if self.lose_reply.swap(false, Ordering::SeqCst) {
            return Err(failure());
        }
        Ok(self.observation(request))
    }
    async fn inspect_memory_capture(
        &self,
        request: &MemoryCaptureRequest,
    ) -> Result<MemoryCaptureObservation, ApiError> {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        if self.captures.load(Ordering::SeqCst) == 0 && self.state.load(Ordering::SeqCst) != REFUSED
        {
            return Err(ApiError::new(
                ErrorCode::NotFound,
                "synthetic original capture absent",
            ));
        }
        Ok(self.observation(request))
    }
    async fn collect_memory_capture(
        &self,
        request: &MemoryCaptureRequest,
    ) -> Result<MemoryCaptureObservation, ApiError> {
        self.collections.fetch_add(1, Ordering::SeqCst);
        if self.collect_fails.load(Ordering::SeqCst) {
            return Err(failure());
        }
        assert!(
            self.removed.load(Ordering::SeqCst),
            "object GC preceded source collection"
        );
        Ok(MemoryCaptureObservation {
            id: request.id,
            source: request.handle.clone(),
            state: MemoryCaptureState::Collected,
        })
    }
    async fn probe(&self) -> RuntimeProfile {
        profile()
    }
    async fn create(&self, _: &Sandbox, _: &CreateSandbox) -> Result<RuntimeHandle, ApiError> {
        panic!("snapshot path attempted ordinary VM creation")
    }
    async fn inspect(&self, _: &RuntimeHandle) -> Result<RuntimeObservation, ApiError> {
        Ok(RuntimeObservation {
            state: if self.removed.load(Ordering::SeqCst) {
                ObservedState::Missing
            } else if self.state.load(Ordering::SeqCst) == READY {
                ObservedState::Paused
            } else {
                ObservedState::Running
            },
            exit_code: None,
            oom_killed: None,
            observed_at: Utc::now(),
        })
    }
    async fn remove(&self, _: &RuntimeHandle) -> Result<(), ApiError> {
        self.removals.fetch_add(1, Ordering::SeqCst);
        if self.remove_fails.load(Ordering::SeqCst) {
            return Err(failure());
        }
        self.removed.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn discover(&self) -> Result<Vec<RuntimeHandle>, ApiError> {
        Ok(Vec::new())
    }
}
#[async_trait]
impl AgentTransport for Backend {
    async fn rpc(
        &self,
        _: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentResponse, ApiError> {
        if matches!(
            request,
            AgentRequest::Start { .. } | AgentRequest::StartSession { .. }
        ) {
            self.starts.fetch_add(1, Ordering::SeqCst);
            panic!("capture replayed workload Start");
        }
        if self.hold_rpc.load(Ordering::SeqCst) {
            self.entered_rpc.notify_one();
            self.release_rpc.notified().await;
        }
        self.rpc_finished.store(true, Ordering::SeqCst);
        Ok(AgentResponse::Ok)
    }
}
#[async_trait]
impl WorkerDriver for Backend {
    async fn profile_snapshot(&self) -> RuntimeProfile {
        profile()
    }
    async fn reap_expired(&self) -> Result<Vec<Uuid>, ApiError> {
        Ok(Vec::new())
    }
}

fn worker(
    store: Store,
    backend: Arc<Backend>,
    artifacts: goldenhoop_artifacts::BlobStore,
) -> Arc<Worker> {
    Arc::new(Worker {
        store,
        drivers: HashMap::from([(profile().id, backend as Arc<dyn WorkerDriver>)]),
        registration: WorkerRegistration {
            id: Uuid::new_v4(),
            endpoint: "http://127.0.0.1:1".into(),
            token: TOKEN.into(),
            heartbeat: Utc::now(),
            profiles: vec![profile()],
        },
        locks: Mutex::new(HashMap::new()),
        concurrency: Arc::new(Semaphore::new(4)),
        cancellations: Mutex::new(HashMap::new()),
        context_closures: Mutex::new(HashMap::new()),
        artifacts,
        artifact_concurrency: Arc::new(Semaphore::new(2)),
        snapshot_concurrency: Arc::new(Semaphore::new(1)),
        network_controller_image: None,
        network_options: None,
        credentials: None,
        network_tasks: Mutex::new(HashMap::new()),
    })
}
async fn checked<F, Fut>(test: F)
where
    F: FnOnce(Arc<Worker>, Arc<Backend>, std::path::PathBuf) -> Fut,
    Fut: Future<Output = ()>,
{
    let directory = tempfile::Builder::new()
        .prefix("gh-snapshot-worker-")
        .tempdir()
        .unwrap();
    let root = directory.path().to_owned();
    let path = root.join("control.db");
    let store = Store::open(&path).await.unwrap();
    let backend = Arc::new(Backend::default());
    let artifacts =
        goldenhoop_artifacts::BlobStore::local(&root.join("blobs"), store.installation_id())
            .unwrap();
    let worker = worker(store, backend.clone(), artifacts);
    let result = AssertUnwindSafe(test(worker.clone(), backend, path))
        .catch_unwind()
        .await;
    worker.store.close().await;
    drop(worker);
    directory.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
async fn source(worker: &Worker) -> (Sandbox, RuntimeHandle) {
    let request = CreateSandbox::new(profile().id, "synthetic-image");
    let created = worker
        .store
        .create_sandbox(&profile(), &request, &Uuid::new_v4().to_string())
        .await
        .unwrap();
    let mut stored = worker.store.sandbox(created.sandbox.id).await.unwrap();
    stored.sandbox.state = SandboxState::Starting;
    worker.store.observe(stored.clone()).await.unwrap();
    let handle = RuntimeHandle {
        sandbox_id: stored.sandbox.id,
        profile: profile().id,
        backend_ref: format!("synthetic-generation-{}", Uuid::new_v4()),
    };
    stored.sandbox.state = SandboxState::Running;
    stored.handle = Some(handle.clone());
    worker.store.observe(stored).await.unwrap();
    (
        worker
            .store
            .sandbox(created.sandbox.id)
            .await
            .unwrap()
            .sandbox,
        handle,
    )
}
async fn step(worker: &Worker, id: Uuid) -> Result<(), ApiError> {
    let source = worker
        .store
        .snapshot(id)
        .await
        .unwrap()
        .snapshot
        .source_sandbox_id;
    let _guard = worker.lock(source).await.lock_owned().await;
    let result = worker.reconcile_snapshot(id).await;
    if let Err(error) = &result {
        worker.snapshot_error(id, error).await.unwrap();
    }
    result
}

#[tokio::test]
async fn accepted_rpc_drains_before_source_fence_and_unrelated_source_remains_usable() {
    checked(|worker,backend,_|async move {
        let (src,handle)=source(&worker).await; let (other,other_handle)=source(&worker).await;
        backend.hold_rpc.store(true,Ordering::SeqCst);
        let (_,admission)=tokio::join!(async {
            let _guard=worker.lock(src.id).await.lock_owned().await;
            worker.rpc(backend.as_ref(),&handle,&AgentRequest::WriteFile { path:"accepted".into(),data_base64:"eA==".into() }).await.unwrap();
        },async {
            backend.entered_rpc.notified().await;
            let serial=worker.lock(src.id).await;
            let request=intent(); let admission=worker.admit_snapshot(src.id,&request,"capture"); tokio::pin!(admission);
            let queued=async {
                // RPC's owned guard and this observer hold two strong refs.
                // The third belongs to admission's pending lock_owned future.
                // Keep polling admission while observing, so its completed SQL
                // read can return the store's single connection to the pool.
                tokio::time::timeout(Duration::from_secs(5),async {
                    while Arc::strong_count(&serial)<3 { tokio::task::yield_now().await; }
                }).await.expect("admission did not queue on the original source mutex");
                assert!(!worker.store.snapshot_source_fenced(src.id).await.unwrap());
            };
            tokio::select! { biased; result=&mut admission=>panic!("admission bypassed the in-flight source mutex: {result:?}"), _=queued=>{} }
            backend.hold_rpc.store(false,Ordering::SeqCst); backend.release_rpc.notify_one();
            let admitted=admission.await.unwrap(); assert!(backend.rpc_finished.load(Ordering::SeqCst)); admitted
        });
        assert!(worker.store.snapshot_source_fenced(src.id).await.unwrap());
        worker.rpc(backend.as_ref(),&other_handle,&AgentRequest::ReadFile { path:"unrelated".into(),max_bytes:64 }).await.unwrap();
        assert!(!worker.store.snapshot_source_fenced(other.id).await.unwrap());
        assert_eq!(backend.captures.load(Ordering::SeqCst),0);
        assert_eq!(worker.admit_snapshot(src.id,&intent(),"capture").await.unwrap().snapshot.id,admission.snapshot.id);
    }).await;
}

#[tokio::test]
async fn lost_capture_reply_survives_database_reopen_and_only_inspects_original_intent() {
    checked(|worker, backend, path| async move {
        let (src, _) = source(&worker).await;
        backend.state.store(READY, Ordering::SeqCst);
        backend.lose_reply.store(true, Ordering::SeqCst);
        let created = worker
            .admit_snapshot(src.id, &intent(), "capture")
            .await
            .unwrap();
        let id = created.snapshot.id;
        assert!(step(&worker, id).await.is_err());
        let unknown = worker.store.snapshot(id).await.unwrap();
        assert_eq!(unknown.snapshot.state, SnapshotState::Unknown);
        assert_eq!(unknown.snapshot.cleanup, CleanupState::Unknown);
        assert!(unknown.source_fenced);
        assert_eq!(
            worker.store.sandbox(src.id).await.unwrap().sandbox.state,
            SandboxState::Running
        );
        worker.store.close().await;
        let reopened = Store::open(&path).await.unwrap();
        let replacement = super::tests::worker(reopened, backend.clone(), worker.artifacts.clone());
        let result = AssertUnwindSafe(async {
            step(&replacement, id).await.unwrap();
            let ready = replacement.store.snapshot_created(id).await.unwrap();
            assert_eq!(ready.snapshot.state, SnapshotState::Ready);
            assert_eq!(ready.operation.state, OperationState::Succeeded);
            assert_eq!(
                replacement
                    .store
                    .sandbox(src.id)
                    .await
                    .unwrap()
                    .sandbox
                    .state,
                SandboxState::Paused
            );
            let public = serde_json::to_string(&ready).unwrap();
            assert!(
                !public.contains("private_host_path") && !public.contains("synthetic-generation")
            );
            assert!(
                replacement
                    .store
                    .snapshot(id)
                    .await
                    .unwrap()
                    .runtime_reference
                    .is_some()
            );
            step(&replacement, id).await.unwrap();
            assert_eq!(backend.captures.load(Ordering::SeqCst), 1);
            assert_eq!(backend.inspections.load(Ordering::SeqCst), 1);
            assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
        })
        .catch_unwind()
        .await;
        replacement.store.close().await;
        drop(replacement);
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    })
    .await;
}

#[tokio::test]
async fn failed_capture_stays_failed_while_source_and_object_collection_recover_independently() {
    checked(|worker, backend, _| async move {
        let (src, handle) = source(&worker).await;
        backend.state.store(FAILED, Ordering::SeqCst);
        backend.remove_fails.store(true, Ordering::SeqCst);
        let created = worker
            .admit_snapshot(src.id, &intent(), "capture")
            .await
            .unwrap();
        let id = created.snapshot.id;
        assert!(step(&worker, id).await.is_err());
        let failed = worker.store.snapshot_created(id).await.unwrap();
        assert_eq!(failed.snapshot.state, SnapshotState::Failed);
        assert_eq!(failed.snapshot.cleanup, CleanupState::Unknown);
        assert_eq!(failed.operation.state, OperationState::Failed);
        assert!(worker.store.snapshot_source_fenced(src.id).await.unwrap());
        assert_eq!(backend.collections.load(Ordering::SeqCst), 0);
        assert_eq!(
            worker
                .store
                .snapshot_capture_collected(id, &handle)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        backend.remove_fails.store(false, Ordering::SeqCst);
        backend.collect_fails.store(true, Ordering::SeqCst);
        assert!(step(&worker, id).await.is_err());
        assert_eq!(
            worker.store.sandbox(src.id).await.unwrap().sandbox.cleanup,
            CleanupState::Complete
        );
        assert!(!worker.store.snapshot_source_fenced(src.id).await.unwrap());
        assert!(
            worker
                .store
                .snapshot_work()
                .await
                .unwrap()
                .iter()
                .any(|s| s.snapshot.id == id)
        );
        let mut changed = handle.clone();
        changed.backend_ref.push_str("-other");
        assert_eq!(
            worker
                .store
                .snapshot_capture_collected(id, &changed)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        backend.collect_fails.store(false, Ordering::SeqCst);
        step(&worker, id).await.unwrap();
        let collected = worker.store.snapshot_created(id).await.unwrap();
        assert_eq!(collected.snapshot.state, SnapshotState::Failed);
        assert_eq!(collected.snapshot.cleanup, CleanupState::Complete);
        assert_eq!(collected.operation.state, OperationState::Failed);
        assert_eq!(collected.snapshot.error.unwrap().message, failure().message);
        assert!(
            !worker
                .store
                .snapshot_work()
                .await
                .unwrap()
                .iter()
                .any(|s| s.snapshot.id == id)
        );
        backend.unsupported.store(true, Ordering::SeqCst);
        assert_eq!(
            worker
                .admit_snapshot(src.id, &intent(), "capture")
                .await
                .unwrap()
                .snapshot
                .id,
            id
        );
        assert_eq!(backend.captures.load(Ordering::SeqCst), 1);
        assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test]
async fn marker_before_send_never_recaptures_and_termination_is_not_starved_by_inspection() {
    checked(|worker, backend, _| async move {
        let (src, handle) = source(&worker).await;
        let id = worker
            .admit_snapshot(src.id, &intent(), "capture")
            .await
            .unwrap()
            .snapshot
            .id;
        assert!(
            worker
                .store
                .begin_snapshot_capture(id, &handle)
                .await
                .unwrap()
                .first_dispatch
        );
        assert!(step(&worker, id).await.is_err());
        assert_eq!(
            worker.store.snapshot(id).await.unwrap().snapshot.state,
            SnapshotState::Unknown
        );
        worker
            .store
            .set_desired(src.id, DesiredState::Terminated, "terminate")
            .await
            .unwrap();
        assert!(step(&worker, id).await.is_err());
        let snapshot = worker.store.snapshot(id).await.unwrap();
        assert!(snapshot.source_collected && !snapshot.source_fenced);
        assert_eq!(snapshot.snapshot.cleanup, CleanupState::Unknown);
        assert_eq!(
            worker.store.sandbox(src.id).await.unwrap().sandbox.cleanup,
            CleanupState::Complete
        );
        assert_eq!(backend.captures.load(Ordering::SeqCst), 0);
        assert_eq!(backend.collections.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inspections.load(Ordering::SeqCst), 2);
        assert_eq!(
            worker
                .admit_snapshot(src.id, &intent(), "capture")
                .await
                .unwrap()
                .snapshot
                .id,
            id
        );
    })
    .await;
}

#[tokio::test]
async fn foreign_reply_retains_original_slot_while_unrelated_rpc_remains_available() {
    checked(|worker, backend, _| async move {
        let (src, _) = source(&worker).await;
        let (other, _) = source(&worker).await;
        let (_, unrelated) = source(&worker).await;
        backend.state.store(READY, Ordering::SeqCst);
        let id = worker
            .admit_snapshot(src.id, &intent(), "capture")
            .await
            .unwrap()
            .snapshot
            .id;
        backend.wrong_source.store(true, Ordering::SeqCst);
        assert!(step(&worker, id).await.is_err());
        assert_eq!(
            worker.store.snapshot(id).await.unwrap().snapshot.state,
            SnapshotState::Unknown
        );
        backend.wrong_source.store(false, Ordering::SeqCst);
        let other_id = worker
            .admit_snapshot(other.id, &intent(), "other")
            .await
            .unwrap()
            .snapshot
            .id;
        let guard = worker.lock(src.id).await.lock_owned().await;
        let mut tasks = JoinSet::new();
        worker
            .schedule_snapshot_work(&mut tasks, &mut 0)
            .await
            .unwrap();
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(
            worker
                .store
                .snapshot(other_id)
                .await
                .unwrap()
                .snapshot
                .state,
            SnapshotState::Pending
        );
        worker
            .rpc(
                backend.as_ref(),
                &unrelated,
                &AgentRequest::ReadFile {
                    path: "unrelated".into(),
                    max_bytes: 64,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            worker.store.snapshot(id).await.unwrap().snapshot.state,
            SnapshotState::Unknown
        );
        drop(guard);
        step(&worker, id).await.unwrap();
        worker
            .schedule_snapshot_work(&mut tasks, &mut 0)
            .await
            .unwrap();
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(
            worker
                .store
                .snapshot(other_id)
                .await
                .unwrap()
                .snapshot
                .state,
            SnapshotState::Ready
        );
        assert_eq!(backend.captures.load(Ordering::SeqCst), 2);
        assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test]
async fn private_admission_requires_authentication_and_pure_preflight_has_no_resource_effect() {
    checked(|worker, backend, _| async move {
        let (src, _) = source(&worker).await;
        let call = InternalSnapshotCall {
            sandbox_id: src.id,
            request: intent(),
            idempotency_key: "capture".into(),
        };
        let body = serde_json::to_vec(&call).unwrap();
        let app = worker.router().unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/snapshots")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        backend.unsupported.store(true, Ordering::SeqCst);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/snapshots")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(worker.store.snapshot_work().await.unwrap().is_empty());
        assert!(!worker.store.snapshot_source_fenced(src.id).await.unwrap());
        backend.unsupported.store(false, Ordering::SeqCst);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/snapshots")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created: SnapshotCreated =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(created.snapshot.state, SnapshotState::Pending);
        assert_eq!(backend.captures.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test]
async fn pending_backend_job_retains_its_dispatch_slot_across_polling_tasks() {
    checked(|worker, backend, _| async move {
        let (first, _) = source(&worker).await;
        let (second, _) = source(&worker).await;
        let one = worker
            .admit_snapshot(first.id, &intent(), "one")
            .await
            .unwrap()
            .snapshot
            .id;
        let two = worker
            .admit_snapshot(second.id, &intent(), "two")
            .await
            .unwrap()
            .snapshot
            .id;
        let mut tasks = JoinSet::new();
        let mut offset = 0;
        worker
            .schedule_snapshot_work(&mut tasks, &mut offset)
            .await
            .unwrap();
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(backend.captures.load(Ordering::SeqCst), 1);
        worker
            .schedule_snapshot_work(&mut tasks, &mut offset)
            .await
            .unwrap();
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(backend.captures.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inspections.load(Ordering::SeqCst), 1);
        let states = [
            worker.store.snapshot(one).await.unwrap().snapshot.state,
            worker.store.snapshot(two).await.unwrap().snapshot.state,
        ];
        assert!(
            states.contains(&SnapshotState::Pending) && states.contains(&SnapshotState::Capturing)
        );
        backend.state.store(READY, Ordering::SeqCst);
        for _ in 0..2 {
            worker
                .schedule_snapshot_work(&mut tasks, &mut offset)
                .await
                .unwrap();
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        }
        assert_eq!(
            worker.store.snapshot(one).await.unwrap().snapshot.state,
            SnapshotState::Ready
        );
        assert_eq!(
            worker.store.snapshot(two).await.unwrap().snapshot.state,
            SnapshotState::Ready
        );
        assert_eq!(backend.captures.load(Ordering::SeqCst), 2);
    })
    .await;
}

#[tokio::test]
async fn durable_refusal_after_missing_send_or_lost_reply_survives_reopen_and_releases_producer_slot()
 {
    for sent in [false, true] {
        checked(move |worker, backend, path| async move {
            let (src, handle) = source(&worker).await;
            let (other, _) = source(&worker).await;
            let id = worker
                .admit_snapshot(src.id, &intent(), "original")
                .await
                .unwrap()
                .snapshot
                .id;
            let queued = worker
                .admit_snapshot(other.id, &intent(), "queued")
                .await
                .unwrap()
                .snapshot
                .id;
            if sent {
                backend.state.store(REFUSED, Ordering::SeqCst);
                backend.lose_reply.store(true, Ordering::SeqCst);
            } else {
                worker
                    .store
                    .begin_snapshot_capture(id, &handle)
                    .await
                    .unwrap();
            }
            assert!(step(&worker, id).await.is_err());
            let unknown = worker.store.snapshot(id).await.unwrap();
            assert_eq!(unknown.snapshot.state, SnapshotState::Unknown);
            assert!(unknown.source_fenced && unknown.capture_refusal.is_none());
            backend.state.store(REFUSED, Ordering::SeqCst);
            backend.wrong_source.store(true, Ordering::SeqCst);
            assert!(step(&worker, id).await.is_err());
            assert!(worker.store.snapshot_source_fenced(src.id).await.unwrap());
            backend.wrong_source.store(false, Ordering::SeqCst);
            worker.store.close().await;
            let replacement = super::tests::worker(
                Store::open(&path).await.unwrap(),
                backend.clone(),
                worker.artifacts.clone(),
            );
            let result = AssertUnwindSafe(async {
                step(&replacement, id).await.unwrap();
                let closed = replacement.store.snapshot(id).await.unwrap();
                assert_eq!(closed.snapshot.state, SnapshotState::Failed);
                assert_eq!(closed.snapshot.cleanup, CleanupState::Complete);
                assert!(!closed.source_collected && !closed.source_fenced);
                assert!(closed.capture_refusal.is_some());
                assert_eq!(replacement.store.snapshot_work().await.unwrap().len(), 1);
                let original = replacement.store.sandbox(src.id).await.unwrap();
                assert_eq!(original.sandbox.state, SandboxState::Running);
                assert_eq!(original.handle.unwrap().backend_ref, handle.backend_ref);
                replacement
                    .rpc(
                        backend.as_ref(),
                        &handle,
                        &AgentRequest::ReadFile {
                            path: "still-usable".into(),
                            max_bytes: 16,
                        },
                    )
                    .await
                    .unwrap();
                backend.unsupported.store(true, Ordering::SeqCst);
                let public = replacement
                    .admit_snapshot(src.id, &intent(), "original")
                    .await
                    .unwrap();
                assert_eq!(public.snapshot.id, id);
                assert_eq!(public.operation.state, OperationState::Failed);
                let body = serde_json::to_string(&public).unwrap();
                assert!(
                    !body.contains("synthetic-permanently-closed-id")
                        && !body.contains(&handle.backend_ref)
                );
                step(&replacement, id).await.unwrap();
                assert_eq!(backend.captures.load(Ordering::SeqCst), usize::from(sent));
                assert_eq!(backend.removals.load(Ordering::SeqCst), 0);
                assert_eq!(backend.collections.load(Ordering::SeqCst), 0);
                backend.unsupported.store(false, Ordering::SeqCst);
                backend.state.store(PENDING, Ordering::SeqCst);
                let mut tasks = JoinSet::new();
                replacement
                    .schedule_snapshot_work(&mut tasks, &mut 0)
                    .await
                    .unwrap();
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
                assert_eq!(
                    replacement
                        .store
                        .snapshot(queued)
                        .await
                        .unwrap()
                        .snapshot
                        .state,
                    SnapshotState::Capturing
                );
                assert_eq!(
                    backend.captures.load(Ordering::SeqCst),
                    usize::from(sent) + 1
                );
                let fresh = replacement
                    .admit_snapshot(src.id, &intent(), "fresh")
                    .await
                    .unwrap();
                assert_ne!(fresh.snapshot.id, id);
                assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
            })
            .catch_unwind()
            .await;
            replacement.store.close().await;
            drop(replacement);
            if let Err(error) = result {
                std::panic::resume_unwind(error);
            }
        })
        .await;
    }
}
